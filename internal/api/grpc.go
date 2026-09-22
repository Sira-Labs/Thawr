package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	thawrv1 "github.com/thedatadudech/thawr/internal/api/proto/thawr/v1"
	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/lock"
)

// Enroller is the control-plane operation behind the Enroll RPC.
type Enroller interface {
	Enroll(ctx context.Context, req control.EnrollRequest) (control.EnrollResult, error)
}

// NetMapSource builds per-peer netmaps.
type NetMapSource interface {
	Build(ctx context.Context, peerID string) (control.NetMap, error)
}

// SyncHub is what the streaming RPCs need from control.Hub.
type SyncHub interface {
	Subscribe(peerID string) (<-chan struct{}, func())
	Connected(peerID string)
	Disconnected(peerID string)
	Changed()
	Options() control.HubOptions
}

// PeerOps are the per-peer operations behind the authenticated RPCs.
type PeerOps interface {
	RotateKey(ctx context.Context, peerID, newPublicKey string, signed *control.SignedRotation) (int64, error)
	Leave(ctx context.Context, peerID string) error
	Touch(ctx context.Context, peerID string) error
	SetClientVersion(ctx context.Context, peerID, version string) error
}

// HubInfo describes the server's own WireGuard endpoint as advertised
// to peers.
type HubInfo struct {
	PublicKey string
	Endpoint  string
	Overlay   netip.Prefix
	// DNS is the hub resolver phones are told to use; invalid when the
	// server runs without one.
	DNS netip.Addr
}

// GRPCDeps are the collaborators of the Control service. Enroller and
// Hub info are required; the rest may be nil for enroll-only tests, in
// which case the other RPCs answer Unimplemented.
type GRPCDeps struct {
	Enroller  Enroller
	Hub       HubInfo
	Version   string
	Logger    *slog.Logger
	NodeAuth  NodeAuth
	NetMaps   NetMapSource
	Sync      SyncHub
	Peers     PeerOps
	Endpoints *control.EndpointTable
	Paths     *control.PathTable
	// Lock enables the network-lock RPCs; nil answers Unimplemented.
	Lock LockOps
	// Routes enables AdvertiseRoutes; nil answers Unimplemented.
	Routes RoutesOps
}

// NewGRPC builds the gRPC server with the Control service registered.
// It is served through Combine on the HTTPS listener.
func NewGRPC(deps GRPCDeps) (*grpc.Server, error) {
	if deps.Enroller == nil {
		return nil, fmt.Errorf("api: Enroller required")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	var opts []grpc.ServerOption
	if deps.NodeAuth != nil {
		opts = append(opts, grpc.ChainUnaryInterceptor(unaryAuth(deps.NodeAuth)), grpc.ChainStreamInterceptor(streamAuth(deps.NodeAuth)))
	}
	srv := grpc.NewServer(opts...)
	thawrv1.RegisterControlServer(srv, &controlServer{deps: deps})
	return srv, nil
}

type controlServer struct {
	thawrv1.UnimplementedControlServer
	deps GRPCDeps
}

func (s *controlServer) Enroll(ctx context.Context, req *thawrv1.EnrollRequest) (*thawrv1.EnrollResponse, error) {
	res, err := s.deps.Enroller.Enroll(ctx, control.EnrollRequest{
		Token:         req.GetToken(),
		PublicKey:     req.GetPublicKey(),
		Hostname:      req.GetHostname(),
		OS:            req.GetOs(),
		Arch:          req.GetArch(),
		ClientVersion: req.GetClientVersion(),
		Name:          req.GetName(),
		RemoteIP:      remoteIP(ctx),
	})
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &thawrv1.EnrollResponse{
		PeerId:           res.Peer.ID,
		Name:             res.Peer.Name,
		Ipv4:             res.Peer.IPv4,
		OverlayCidr:      s.deps.Hub.Overlay.String(),
		NodeSecret:       res.NodeSecret,
		HubPublicKey:     s.deps.Hub.PublicKey,
		HubEndpoint:      s.deps.Hub.Endpoint,
		ServerVersion:    s.deps.Version,
		NetmapGeneration: res.Generation,
	}, nil
}

// Sync streams the caller's netmap: a full map now, a full map on every
// change, and a keepalive copy every KeepaliveInterval.
func (s *controlServer) Sync(req *thawrv1.SyncRequest, stream grpc.ServerStreamingServer[thawrv1.NetMap]) error {
	if s.deps.NetMaps == nil || s.deps.Sync == nil {
		return status.Error(codes.Unimplemented, "sync not available")
	}
	ctx := stream.Context()
	me, ok := peerFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "node secret required")
	}
	log := s.deps.Logger.With("peer", me.Name, "peer_id", me.ID)
	log.Info("sync connected", "client_generation", req.GetGeneration(), "client_version", req.GetClientVersion(), "remote", remoteIP(ctx))
	if s.deps.Lock != nil {
		if k := req.GetLockKey(); k != "" {
			if _, err := lock.ParsePublicKey(k); err != nil {
				return status.Error(codes.InvalidArgument, "lock_key: "+err.Error())
			}
		}
		s.deps.Lock.ReportKey(me.ID, req.GetLockKey())
	}

	wake, unsubscribe := s.deps.Sync.Subscribe(me.ID)
	defer unsubscribe()
	s.deps.Sync.Connected(me.ID)
	defer s.deps.Sync.Disconnected(me.ID)
	if s.deps.Peers != nil {
		if err := s.deps.Peers.Touch(ctx, me.ID); err != nil {
			log.Warn("touch failed", "err", err)
		}
		if v := req.GetClientVersion(); v != "" && v != me.ClientVersion {
			if err := s.deps.Peers.SetClientVersion(ctx, me.ID, v); err != nil {
				log.Warn("record client version failed", "err", err)
			}
		}
	}

	keepalive := time.NewTicker(s.deps.Sync.Options().KeepaliveInterval)
	defer keepalive.Stop()
	send := func(isKeepalive bool) error {
		nm, err := s.deps.NetMaps.Build(ctx, me.ID)
		if errors.Is(err, control.ErrNotFound) {
			log.Info("sync closed: peer removed")
			return status.Error(codes.PermissionDenied, "peer removed")
		}
		if err != nil {
			log.Error("build netmap", "err", err)
			return status.Error(codes.Internal, "internal error")
		}
		msg := netMapToProto(nm)
		msg.Keepalive = isKeepalive
		msg.ServerVersion = s.deps.Version
		if err := stream.Send(msg); err != nil {
			return err
		}
		if !isKeepalive {
			log.Debug("netmap sent", "generation", nm.Generation, "peers", len(nm.Peers))
		}
		return nil
	}
	if err := send(false); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			log.Info("sync disconnected")
			return nil
		case <-wake:
			if err := send(false); err != nil {
				return err
			}
		case <-keepalive.C:
			if err := send(true); err != nil {
				return err
			}
		}
	}
}

func (s *controlServer) ReportEndpoints(ctx context.Context, req *thawrv1.EndpointReport) (*thawrv1.Empty, error) {
	if s.deps.Endpoints == nil || s.deps.Sync == nil {
		return nil, status.Error(codes.Unimplemented, "endpoint reports not available")
	}
	me, ok := peerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "node secret required")
	}
	eps, err := endpointsFromProto(req.GetEndpoints())
	if err != nil {
		return nil, s.toStatus(err)
	}
	if req.GetListenPort() > 65535 {
		return nil, status.Error(codes.InvalidArgument, "listen_port out of range")
	}
	changed, err := s.deps.Endpoints.Set(me.ID, eps, req.GetSymmetric(), uint16(req.GetListenPort())) //nolint:gosec // range-checked above
	if err != nil {
		return nil, s.toStatus(err)
	}
	if changed {
		s.deps.Logger.Debug("endpoints updated", "peer", me.Name, "count", len(eps), "symmetric", req.GetSymmetric())
		s.deps.Sync.Changed()
	}
	return &thawrv1.Empty{}, nil
}

func (s *controlServer) ReportPath(ctx context.Context, req *thawrv1.PathReport) (*thawrv1.Empty, error) {
	if s.deps.Paths == nil {
		return nil, status.Error(codes.Unimplemented, "path reports not available")
	}
	me, ok := peerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "node secret required")
	}
	if len(req.GetPaths()) > 4096 {
		return nil, status.Error(codes.InvalidArgument, "too many paths")
	}
	paths := make([]control.PathState, 0, len(req.GetPaths()))
	for _, p := range req.GetPaths() {
		switch p.GetState() {
		case "direct", "relay", "probing", "idle", "unreachable", "hub":
		default:
			return nil, status.Errorf(codes.InvalidArgument, "unknown path state %q", p.GetState())
		}
		paths = append(paths, control.PathState{PeerID: p.GetPeerId(), State: p.GetState(), Endpoint: p.GetEndpoint()})
	}
	s.deps.Paths.Set(me.ID, paths)
	return &thawrv1.Empty{}, nil
}

func (s *controlServer) RotateKey(ctx context.Context, req *thawrv1.RotateKeyRequest) (*thawrv1.RotateKeyResponse, error) {
	if s.deps.Peers == nil {
		return nil, status.Error(codes.Unimplemented, "key rotation not available")
	}
	me, ok := peerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "node secret required")
	}
	var signed *control.SignedRotation
	if req.GetSignerKey() != "" || req.GetSignature() != "" {
		signer, err := lock.ParsePublicKey(req.GetSignerKey())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		sig, err := lock.ParseSignature(req.GetSignature())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		signed = &control.SignedRotation{Signer: signer, Signature: sig}
	}
	gen, err := s.deps.Peers.RotateKey(ctx, me.ID, req.GetNewPublicKey(), signed)
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &thawrv1.RotateKeyResponse{Generation: gen}, nil
}

func (s *controlServer) Leave(ctx context.Context, _ *thawrv1.Empty) (*thawrv1.Empty, error) {
	if s.deps.Peers == nil {
		return nil, status.Error(codes.Unimplemented, "leave not available")
	}
	me, ok := peerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "node secret required")
	}
	if err := s.deps.Peers.Leave(ctx, me.ID); err != nil {
		return nil, s.toStatus(err)
	}
	return &thawrv1.Empty{}, nil
}

// toStatus maps control errors to gRPC codes without leaking internals.
func (s *controlServer) toStatus(err error) error {
	switch {
	case errors.Is(err, control.ErrInvalidToken):
		return status.Error(codes.PermissionDenied, control.ErrInvalidToken.Error())
	case errors.Is(err, control.ErrValidation):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, control.ErrRateLimited):
		return status.Error(codes.ResourceExhausted, control.ErrRateLimited.Error())
	case errors.Is(err, control.ErrVersion):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, control.ErrExhausted):
		return status.Error(codes.ResourceExhausted, "no free overlay address")
	case errors.Is(err, control.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, control.ErrForbidden):
		return status.Error(codes.PermissionDenied, err.Error())
	}
	s.deps.Logger.Error("rpc failed", "err", err)
	return status.Error(codes.Internal, "internal error")
}

// remoteIP extracts the caller's IP from the gRPC peer info.
func remoteIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}
