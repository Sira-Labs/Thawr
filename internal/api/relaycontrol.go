package api

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	thawrv1 "github.com/sira-labs/thawr/internal/api/proto/thawr/v1"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

// relayServicePrefix is the method prefix of the RelayControl service.
// Its RPCs authenticate with a relay token or a relay secret in their
// own handlers, so the node-secret interceptors let them through.
const relayServicePrefix = "/thawr.v1.RelayControl/"

// RelayOps is what the RelayControl service needs from control.Relays.
type RelayOps interface {
	Register(ctx context.Context, req control.RelayRegistration) (control.RegisteredRelay, error)
	Authenticate(ctx context.Context, secret string) (store.Relay, error)
	Attach(ctx context.Context, relayID string, hello control.RelayHello) (uint64, error)
	Current(relayID string, epoch uint64) bool
	Heartbeat(ctx context.Context, relayID string, epoch uint64, stats control.RelayStats) error
	Detach(ctx context.Context, relayID string, epoch uint64) error
	Admit(ctx context.Context, relayID string, ticket []byte) (store.Peer, error)
	SessionPeer(ctx context.Context, peerID string) (store.Peer, error)
}

// RelayDeps are the collaborators of the RelayControl service.
type RelayDeps struct {
	Relays RelayOps
	// NetMaps tells which keys an admitted device may exchange packets
	// with: the peers of its own netmap.
	NetMaps NetMapSource
	// Sync wakes the stream on every netmap change.
	Sync SyncHub
	// MaxBytesPerSecond is relay.max_bytes_per_second, passed on to the
	// relay with every admission.
	MaxBytesPerSecond int
	Version           string
	Logger            *slog.Logger
}

type relayControlServer struct {
	thawrv1.UnimplementedRelayControlServer
	deps RelayDeps
}

// relaySession is one device admitted at the attached relay.
type relaySession struct {
	peerID  string
	key     wg.Key
	visible [][]byte
}

func (s *relayControlServer) Register(ctx context.Context, req *thawrv1.RegisterRelayRequest) (*thawrv1.RegisterRelayResponse, error) {
	res, err := s.deps.Relays.Register(ctx, control.RelayRegistration{
		Token: req.GetToken(), Name: req.GetName(), URL: req.GetPublicUrl(), Fingerprint: req.GetTlsFingerprint(), Version: req.GetVersion(),
	})
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &thawrv1.RegisterRelayResponse{RelayId: res.Relay.ID, Name: res.Relay.Name, RelaySecret: res.Secret, ServerVersion: s.deps.Version}, nil
}

// Attach serves a relay's control stream: it marks the relay online,
// answers admissions, pushes the visible keys of every admitted device
// when a netmap generation changes them, and revokes a device that was
// deleted or rotated its key.
func (s *relayControlServer) Attach(stream grpc.BidiStreamingServer[thawrv1.RelayEvent, thawrv1.RelayDirective]) error {
	ctx := stream.Context()
	relay, err := s.authenticate(ctx)
	if err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "the first event must be hello")
	}
	epoch, err := s.deps.Relays.Attach(ctx, relay.ID, control.RelayHello{URL: hello.GetPublicUrl(), Fingerprint: hello.GetTlsFingerprint(), Version: hello.GetVersion()})
	if err != nil {
		return s.toStatus(err)
	}
	log := s.deps.Logger.With("relay", relay.Name, "relay_id", relay.ID)
	log.Info("relay attached", "remote", remoteIP(ctx), "version", hello.GetVersion())
	defer func() {
		// ctx is done when the stream ends; the bookkeeping still has
		// to reach the database.
		if err := s.deps.Relays.Detach(context.WithoutCancel(ctx), relay.ID, epoch); err != nil {
			log.Warn("relay detach failed", "err", err)
		}
		log.Info("relay detached")
	}()

	wake, unsubscribe := s.deps.Sync.Subscribe("relay:" + relay.ID)
	defer unsubscribe()
	events := make(chan *thawrv1.RelayEvent)
	recvErr := make(chan error, 1)
	go func() {
		for {
			ev, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	sessions := map[string]*relaySession{}
	for {
		select {
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case err := <-recvErr:
			return err
		case ev := <-events:
			if !s.deps.Relays.Current(relay.ID, epoch) {
				return status.Error(codes.Aborted, "relay removed or attached again elsewhere")
			}
			if err := s.handleEvent(ctx, stream, relay.ID, epoch, ev, sessions, log); err != nil {
				return err
			}
		case <-wake:
			if !s.deps.Relays.Current(relay.ID, epoch) {
				return status.Error(codes.Aborted, "relay removed or attached again elsewhere")
			}
			if err := s.refreshSessions(ctx, stream, sessions, log); err != nil {
				return err
			}
		}
	}
}

func (s *relayControlServer) handleEvent(ctx context.Context, stream grpc.BidiStreamingServer[thawrv1.RelayEvent, thawrv1.RelayDirective],
	relayID string, epoch uint64, ev *thawrv1.RelayEvent, sessions map[string]*relaySession, log *slog.Logger) error {
	switch e := ev.GetEvent().(type) {
	case *thawrv1.RelayEvent_Hello:
		return status.Error(codes.InvalidArgument, "hello may only open the stream")
	case *thawrv1.RelayEvent_Heartbeat:
		hb := e.Heartbeat
		err := s.deps.Relays.Heartbeat(ctx, relayID, epoch, control.RelayStats{Sessions: int(hb.GetSessions()), Frames: hb.GetFrames(), Bytes: hb.GetBytes(), Drops: hb.GetDrops()})
		if errors.Is(err, control.ErrNotFound) {
			// Replaced or deleted between the loop's check and here.
			return status.Error(codes.Aborted, "relay removed or attached again elsewhere")
		}
		if err != nil {
			return s.toStatus(err)
		}
	case *thawrv1.RelayEvent_Admit:
		return s.admit(ctx, stream, relayID, e.Admit, sessions, log)
	case *thawrv1.RelayEvent_Closed:
		for id, sess := range sessions {
			if bytes.Equal(sess.key[:], e.Closed.GetPeerKey()) {
				delete(sessions, id)
			}
		}
	case *thawrv1.RelayEvent_Absent:
		// TODO(2026-11-22): turn into a reach request for dst once the
		// relay node sends it (spec 016, story S8-3).
		log.Debug("relay: absent destination reported")
	default:
		return status.Error(codes.InvalidArgument, "empty event")
	}
	return nil
}

// admit answers one admission. A ticket that opens nothing is refused
// without a reason; so is one the server could not check, since the
// relay must not let a device in on the server's failure.
func (s *relayControlServer) admit(ctx context.Context, stream grpc.BidiStreamingServer[thawrv1.RelayEvent, thawrv1.RelayDirective],
	relayID string, req *thawrv1.RelayAdmit, sessions map[string]*relaySession, log *slog.Logger) error {
	refuse := func() error {
		return stream.Send(&thawrv1.RelayDirective{Directive: &thawrv1.RelayDirective_Refused{Refused: &thawrv1.RelayRefused{RequestId: req.GetRequestId()}}})
	}
	p, err := s.deps.Relays.Admit(ctx, relayID, req.GetTicket())
	if errors.Is(err, control.ErrForbidden) {
		return refuse()
	}
	if err != nil {
		log.Error("relay admission failed", "err", err)
		return refuse()
	}
	key, err := wg.ParseKey(p.PublicKey)
	if err != nil {
		log.Error("relay admission: peer key unreadable", "peer_id", p.ID, "err", err)
		return refuse()
	}
	visible, gen, err := s.visibleKeys(ctx, p.ID)
	if err != nil {
		log.Error("relay admission: visibility failed", "peer_id", p.ID, "err", err)
		return refuse()
	}
	// A device that rotated its key and came back before the netmap
	// change reached this loop: the relay knows sessions by key only,
	// so the session under the old key is revoked here or never.
	if old, ok := sessions[p.ID]; ok && old.key != key {
		if err := stream.Send(&thawrv1.RelayDirective{Directive: &thawrv1.RelayDirective_Revoke{Revoke: &thawrv1.RelayRevoke{PeerKey: old.key[:]}}}); err != nil {
			return err
		}
	}
	sessions[p.ID] = &relaySession{peerID: p.ID, key: key, visible: visible}
	return stream.Send(&thawrv1.RelayDirective{Directive: &thawrv1.RelayDirective_Admitted{Admitted: &thawrv1.RelayAdmitted{
		RequestId: req.GetRequestId(), PeerKey: key[:], VisibleKeys: visible, Generation: gen,
		MaxBytesPerSecond: uint64(max(s.deps.MaxBytesPerSecond, 0)),
	}}})
}

// refreshSessions runs after a netmap change: a device that is gone or
// has a new key is revoked, and one whose visible keys changed gets the
// new set.
func (s *relayControlServer) refreshSessions(ctx context.Context, stream grpc.BidiStreamingServer[thawrv1.RelayEvent, thawrv1.RelayDirective],
	sessions map[string]*relaySession, log *slog.Logger) error {
	ids := make([]string, 0, len(sessions))
	for id := range sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		sess := sessions[id]
		revoke := func() error {
			delete(sessions, id)
			return stream.Send(&thawrv1.RelayDirective{Directive: &thawrv1.RelayDirective_Revoke{Revoke: &thawrv1.RelayRevoke{PeerKey: sess.key[:]}}})
		}
		p, err := s.deps.Relays.SessionPeer(ctx, id)
		if errors.Is(err, control.ErrNotFound) {
			if err := revoke(); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			log.Error("relay refresh: peer lookup failed", "peer_id", id, "err", err)
			return status.Error(codes.Internal, "internal error")
		}
		if key, err := wg.ParseKey(p.PublicKey); err != nil || key != sess.key {
			if err := revoke(); err != nil {
				return err
			}
			continue
		}
		visible, gen, err := s.visibleKeys(ctx, id)
		if errors.Is(err, control.ErrNotFound) {
			if err := revoke(); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			log.Error("relay refresh: visibility failed", "peer_id", id, "err", err)
			return status.Error(codes.Internal, "internal error")
		}
		if sameKeys(visible, sess.visible) {
			continue
		}
		sess.visible = visible
		err = stream.Send(&thawrv1.RelayDirective{Directive: &thawrv1.RelayDirective_Visibility{Visibility: &thawrv1.RelayVisibility{
			PeerKey: sess.key[:], VisibleKeys: visible, Generation: gen}}})
		if err != nil {
			return err
		}
	}
	return nil
}

// visibleKeys lists the WireGuard keys of the peers in peerID's netmap,
// sorted, with the generation they belong to. A key that cannot be
// parsed is left out: the relay then forwards nothing to it.
func (s *relayControlServer) visibleKeys(ctx context.Context, peerID string) ([][]byte, int64, error) {
	nm, err := s.deps.NetMaps.Build(ctx, peerID)
	if err != nil {
		return nil, 0, err
	}
	keys := make([][]byte, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		k, err := wg.ParseKey(p.PublicKey)
		if err != nil {
			continue
		}
		keys = append(keys, k[:])
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
	return keys, nm.Generation, nil
}

func sameKeys(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// authenticate resolves the bearer relay secret into a relay. A node
// secret is not one: it names a row in another table.
func (s *relayControlServer) authenticate(ctx context.Context) (store.Relay, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	var secret string
	for _, v := range md.Get("authorization") {
		if sec, ok := strings.CutPrefix(v, "Bearer "); ok {
			secret = sec
		}
	}
	if secret == "" {
		return store.Relay{}, status.Error(codes.Unauthenticated, "relay secret required")
	}
	relay, err := s.deps.Relays.Authenticate(ctx, secret)
	if errors.Is(err, control.ErrForbidden) {
		return store.Relay{}, status.Error(codes.Unauthenticated, "invalid relay secret")
	}
	if err != nil {
		s.deps.Logger.Error("relay authentication failed", "err", err)
		return store.Relay{}, status.Error(codes.Internal, "internal error")
	}
	return relay, nil
}

// toStatus maps control errors to gRPC codes without leaking internals.
func (s *relayControlServer) toStatus(err error) error {
	switch {
	case errors.Is(err, control.ErrInvalidToken):
		return status.Error(codes.PermissionDenied, control.ErrInvalidToken.Error())
	case errors.Is(err, control.ErrValidation):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, control.ErrNotFound):
		return status.Error(codes.NotFound, "relay not attached")
	case errors.Is(err, control.ErrForbidden):
		return status.Error(codes.PermissionDenied, control.ErrForbidden.Error())
	}
	s.deps.Logger.Error("relay rpc failed", "err", err)
	return status.Error(codes.Internal, "internal error")
}
