package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	thawrv1 "github.com/sira-labs/thawr/internal/api/proto/thawr/v1"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

// relayCtlEnv is a control plane with the relay service behind bufconn.
type relayCtlEnv struct {
	t        *testing.T
	st       *store.Store
	hub      *control.Hub
	registry *control.Registry
	tokens   *control.Tokens
	relays   *control.Relays
	control  thawrv1.ControlClient
	relay    thawrv1.RelayControlClient
	admin    control.Principal
}

type relayStream = grpc.BidiStreamingClient[thawrv1.RelayEvent, thawrv1.RelayDirective]

func newRelayCtlEnv(t *testing.T) *relayCtlEnv {
	t.Helper()
	return newRelayCtlEnvWith(t, func(p PeerOps) PeerOps { return p })
}

// newRelayCtlEnvWith lets a test put something between the Control
// service and the registry.
func newRelayCtlEnvWith(t *testing.T, wrap func(PeerOps) PeerOps) *relayCtlEnv {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now
	users, err := control.NewUsers(st, now, quiet)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := users.Create(ctx, control.LocalAdmin, "markus", store.RoleAdmin, "adminpassword")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.Create(ctx, control.LocalAdmin, "lena", store.RoleMember, "lenapassword"); err != nil {
		t.Fatal(err)
	}
	hub, err := control.NewHub(ctx, st, now, quiet, control.HubOptions{Coalesce: 10 * time.Millisecond, KeepaliveInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	overlay := netip.MustParsePrefix("100.64.0.0/10")
	relays := control.NewRelays(st, now, quiet).WithNotifier(hub)
	registry := control.NewRegistry(st, quiet).WithNotifier(hub).WithTicketForgetter(relays)
	enroller := control.NewEnroller(st, now, quiet, overlay, "").WithNotifier(hub)
	endpoints := control.NewEndpointTable(now)
	hubInfo := control.HubConfig{PublicKey: testHubKey, Endpoint: "vpn:51820", Address: netip.MustParseAddr("100.64.0.1"), Overlay: overlay}
	// OwnerVisibility: peers of one owner see each other, nobody else.
	builder := control.NewNetMapBuilder(st, control.OwnerVisibility{}, endpoints, hub, hubInfo, hub.Generation).WithRelayTickets(relays)
	srv, err := NewGRPC(GRPCDeps{
		Enroller: enroller, Hub: HubInfo{PublicKey: testHubKey, Endpoint: "vpn:51820", Overlay: overlay}, Logger: quiet,
		NodeAuth: registry, NetMaps: builder, Sync: hub, Peers: wrap(registry), Endpoints: endpoints, Paths: control.NewPathTable(now),
		Relay: &RelayDeps{Relays: relays, NetMaps: builder, Sync: hub, MaxBytesPerSecond: 4096, Version: "9.9.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return ln.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &relayCtlEnv{t: t, st: st, hub: hub, registry: registry, tokens: control.NewTokens(st, now, quiet), relays: relays,
		control: thawrv1.NewControlClient(conn), relay: thawrv1.NewRelayControlClient(conn),
		admin: control.Principal{UserID: admin.ID, Name: admin.Name, Role: admin.Role}}
}

// register creates a relay token and registers a relay over the RPC.
func (e *relayCtlEnv) register(name string) *thawrv1.RegisterRelayResponse {
	e.t.Helper()
	ctx := context.Background()
	tok, err := e.relays.CreateToken(ctx, e.admin, name, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	resp, err := e.relay.Register(ctx, &thawrv1.RegisterRelayRequest{Token: tok.Secret, PublicUrl: restRelayURL, TlsFingerprint: restRelayFP, Version: "0.2.0"})
	if err != nil {
		e.t.Fatalf("register %s: %v", name, err)
	}
	return resp
}

// attach opens the control stream and sends hello; the caller cancels.
func (e *relayCtlEnv) attach(secret string) (relayStream, context.CancelFunc) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(authCtx(secret))
	e.t.Cleanup(cancel)
	stream, err := e.relay.Attach(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	e.send(stream, &thawrv1.RelayEvent{Event: &thawrv1.RelayEvent_Hello{Hello: &thawrv1.RelayHello{Version: "0.2.0", PublicUrl: restRelayURL, TlsFingerprint: restRelayFP}}})
	return stream, cancel
}

func (e *relayCtlEnv) send(stream relayStream, ev *thawrv1.RelayEvent) {
	e.t.Helper()
	if err := stream.Send(ev); err != nil {
		e.t.Fatalf("send: %v", err)
	}
}

// recv returns the next directive, or the stream's error.
func (e *relayCtlEnv) recv(stream relayStream) (*thawrv1.RelayDirective, error) {
	e.t.Helper()
	const wait = 3 * time.Second
	type result struct {
		d   *thawrv1.RelayDirective
		err error
	}
	ch := make(chan result, 1)
	go func() {
		d, err := stream.Recv()
		ch <- result{d, err}
	}()
	select {
	case r := <-ch:
		return r.d, r.err
	case <-time.After(wait):
		e.t.Fatalf("no directive within %s", wait)
		return nil, nil
	}
}

func (e *relayCtlEnv) waitOnline(n int) {
	e.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		on, err := e.relays.Online(context.Background())
		if err != nil {
			e.t.Fatal(err)
		}
		if len(on) == n {
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("%d relays online, want %d", len(on), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// peer enrols a device for owner and returns its id and public key.
func (e *relayCtlEnv) peer(owner, hostname string) (string, wg.Key) {
	e.t.Helper()
	ctx := context.Background()
	tok, err := e.tokens.Create(ctx, e.admin, control.TokenRequest{OwnerName: owner, Kind: "human"})
	if err != nil {
		e.t.Fatal(err)
	}
	key, err := wg.GenerateKey()
	if err != nil {
		e.t.Fatal(err)
	}
	resp, err := e.control.Enroll(ctx, &thawrv1.EnrollRequest{Token: tok.Secret, PublicKey: key.PublicKey().String(), Hostname: hostname, ClientVersion: "0.2.0", RelayNodes: true})
	if err != nil {
		e.t.Fatalf("enroll %s: %v", hostname, err)
	}
	return resp.GetPeerId(), key.PublicKey()
}

func (e *relayCtlEnv) ticket(peerID string) []byte {
	e.t.Helper()
	g, err := e.relays.Tickets(context.Background(), peerID)
	if err != nil || len(g) != 1 {
		e.t.Fatalf("tickets: %v %v", g, err)
	}
	return g[0].Ticket
}

func admitEvent(id uint64, ticket []byte) *thawrv1.RelayEvent {
	return &thawrv1.RelayEvent{Event: &thawrv1.RelayEvent_Admit{Admit: &thawrv1.RelayAdmit{RequestId: id, Ticket: ticket}}}
}

func keyList(keys [][]byte) string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		var key wg.Key
		copy(key[:], k)
		out = append(out, key.String()[:8])
	}
	return strings.Join(out, ",")
}

func TestRelayRegisterRPC(t *testing.T) {
	env := newRelayCtlEnv(t)
	ctx := context.Background()
	resp := env.register("riyadh-1")
	if resp.GetName() != "riyadh-1" || !strings.HasPrefix(resp.GetRelayId(), "rl_") || resp.GetRelaySecret() == "" || resp.GetServerVersion() != "9.9.9" {
		t.Fatalf("response: id=%q name=%q version=%q", resp.GetRelayId(), resp.GetName(), resp.GetServerVersion())
	}
	if r, err := env.relays.Authenticate(ctx, resp.GetRelaySecret()); err != nil || r.ID != resp.GetRelayId() {
		t.Errorf("the returned secret does not authenticate: %v", err)
	}

	peerToken, err := env.tokens.Create(ctx, env.admin, control.TokenRequest{OwnerName: "markus", Kind: "human"})
	if err != nil {
		t.Fatal(err)
	}
	relayToken, err := env.relays.CreateToken(ctx, env.admin, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	// A peer token registers no relay and a relay token enrols no peer;
	// both answers are the same code and message.
	_, errRelay := env.relay.Register(ctx, &thawrv1.RegisterRelayRequest{Token: peerToken.Secret, Name: "sneaky", PublicUrl: restRelayURL, TlsFingerprint: restRelayFP})
	key, _ := wg.GenerateKey()
	_, errPeer := env.control.Enroll(ctx, &thawrv1.EnrollRequest{Token: relayToken.Secret, PublicKey: key.PublicKey().String(), Hostname: "box"})
	if status.Code(errRelay) != codes.PermissionDenied || status.Code(errPeer) != codes.PermissionDenied ||
		status.Convert(errRelay).Message() != status.Convert(errPeer).Message() {
		t.Errorf("token kinds: register=%v enroll=%v", errRelay, errPeer)
	}
	for name, tc := range map[string]struct {
		req  *thawrv1.RegisterRelayRequest
		want codes.Code
	}{
		"no token":      {&thawrv1.RegisterRelayRequest{Name: "a", PublicUrl: restRelayURL, TlsFingerprint: restRelayFP}, codes.PermissionDenied},
		"unknown token": {&thawrv1.RegisterRelayRequest{Token: "thawr_relay_nope", Name: "a", PublicUrl: restRelayURL, TlsFingerprint: restRelayFP}, codes.PermissionDenied},
		"http url":      {&thawrv1.RegisterRelayRequest{Token: relayToken.Secret, Name: "a", PublicUrl: "http://r.example.com:443", TlsFingerprint: restRelayFP}, codes.InvalidArgument},
		"bad fp":        {&thawrv1.RegisterRelayRequest{Token: relayToken.Secret, Name: "a", PublicUrl: restRelayURL, TlsFingerprint: "sha256:zz"}, codes.InvalidArgument},
		"no name":       {&thawrv1.RegisterRelayRequest{Token: relayToken.Secret, PublicUrl: restRelayURL, TlsFingerprint: restRelayFP}, codes.InvalidArgument},
	} {
		if _, err := env.relay.Register(ctx, tc.req); status.Code(err) != tc.want {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
	}
}

// TestRelayControlAuth: Attach takes a relay secret and nothing else,
// and a relay secret opens nothing on the Control service.
func TestRelayControlAuth(t *testing.T) {
	env := newRelayCtlEnv(t)
	reg := env.register("riyadh-1")
	_, nodeSecret := func() (string, string) {
		tok, err := env.tokens.Create(context.Background(), env.admin, control.TokenRequest{OwnerName: "markus", Kind: "human"})
		if err != nil {
			t.Fatal(err)
		}
		key, _ := wg.GenerateKey()
		resp, err := env.control.Enroll(context.Background(), &thawrv1.EnrollRequest{Token: tok.Secret, PublicKey: key.PublicKey().String(), Hostname: "box"})
		if err != nil {
			t.Fatal(err)
		}
		return resp.GetPeerId(), resp.GetNodeSecret()
	}()

	for name, ctx := range map[string]context.Context{
		"no credential":   context.Background(),
		"unknown secret":  authCtx("nope"),
		"a node secret":   authCtx(nodeSecret),
		"the relay token": authCtx("thawr_relay_whatever"),
	} {
		stream, err := env.relay.Attach(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.recv(stream); status.Code(err) != codes.Unauthenticated {
			t.Errorf("%s: %v", name, err)
		}
	}
	env.waitOnline(0)

	sync, err := env.control.Sync(authCtx(reg.GetRelaySecret()), &thawrv1.SyncRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sync.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Errorf("relay secret on Control.Sync: %v", err)
	}
	if _, err := env.control.Leave(authCtx(reg.GetRelaySecret()), &thawrv1.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("relay secret on Control.Leave: %v", err)
	}
}

func TestAttachOnlineOffline(t *testing.T) {
	env := newRelayCtlEnv(t)
	reg := env.register("riyadh-1")

	// The first event must be hello.
	ctx, cancel := context.WithCancel(authCtx(reg.GetRelaySecret()))
	defer cancel()
	stream, err := env.relay.Attach(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env.send(stream, &thawrv1.RelayEvent{Event: &thawrv1.RelayEvent_Heartbeat{Heartbeat: &thawrv1.RelayHeartbeat{}}})
	if _, err := env.recv(stream); status.Code(err) != codes.InvalidArgument {
		t.Errorf("heartbeat before hello: %v", err)
	}
	env.waitOnline(0)

	stream, stop := env.attach(reg.GetRelaySecret())
	env.waitOnline(1)
	env.send(stream, &thawrv1.RelayEvent{Event: &thawrv1.RelayEvent_Heartbeat{Heartbeat: &thawrv1.RelayHeartbeat{Sessions: 2, Frames: 9, Bytes: 1234, Drops: 1}}})
	deadline := time.Now().Add(3 * time.Second)
	for {
		st, err := env.relays.Get(context.Background(), env.admin, "riyadh-1")
		if err != nil {
			t.Fatal(err)
		}
		if st.Stats.Bytes == 1234 && st.Stats.Sessions == 2 && st.Relay.Version == "0.2.0" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("heartbeat not recorded: %+v", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A second hello is refused and ends the stream, which takes the
	// relay offline like any other end of it.
	env.send(stream, &thawrv1.RelayEvent{Event: &thawrv1.RelayEvent_Hello{Hello: &thawrv1.RelayHello{PublicUrl: restRelayURL, TlsFingerprint: restRelayFP}}})
	if _, err := env.recv(stream); status.Code(err) != codes.InvalidArgument {
		t.Errorf("second hello: %v", err)
	}
	env.waitOnline(0)
	stop()

	// Closing the stream from the relay's side does the same.
	_, stop = env.attach(reg.GetRelaySecret())
	env.waitOnline(1)
	stop()
	env.waitOnline(0)
}

func TestAttachAdmitRefuse(t *testing.T) {
	env := newRelayCtlEnv(t)
	reg := env.register("riyadh-1")
	other := env.register("berlin-1")
	stream, _ := env.attach(reg.GetRelaySecret())
	otherStream, _ := env.attach(other.GetRelaySecret())
	env.waitOnline(2)

	aliceID, aliceKey := env.peer("markus", "alice")
	_, bobKey := env.peer("markus", "bob")
	_, carolKey := env.peer("lena", "carol")
	grants, err := env.relays.Tickets(context.Background(), aliceID)
	if err != nil || len(grants) != 2 {
		t.Fatalf("tickets: %v %v", grants, err)
	}
	// Ordered by relay name: berlin-1, riyadh-1.
	forBerlin, forRiyadh := grants[0].Ticket, grants[1].Ticket

	env.send(stream, admitEvent(7, forRiyadh))
	d, err := env.recv(stream)
	if err != nil {
		t.Fatal(err)
	}
	ad := d.GetAdmitted()
	if ad == nil || ad.GetRequestId() != 7 || !bytes.Equal(ad.GetPeerKey(), aliceKey[:]) || ad.GetMaxBytesPerSecond() != 4096 || ad.GetGeneration() == 0 {
		t.Fatalf("admitted: %+v", d)
	}
	// Alice sees bob (same owner), not carol.
	if len(ad.GetVisibleKeys()) != 1 || !bytes.Equal(ad.GetVisibleKeys()[0], bobKey[:]) || bytes.Equal(ad.GetVisibleKeys()[0], carolKey[:]) {
		t.Errorf("visible keys: %s", keyList(ad.GetVisibleKeys()))
	}

	for id, ticket := range map[uint64][]byte{
		8:  forBerlin,                               // another relay's ticket
		9:  bytes.Repeat([]byte{1}, len(forRiyadh)), // unknown
		10: forRiyadh[:5],                           // malformed
		11: nil,
	} {
		env.send(stream, admitEvent(id, ticket))
		d, err := env.recv(stream)
		if err != nil {
			t.Fatal(err)
		}
		if d.GetRefused().GetRequestId() != id {
			t.Errorf("request %d: %+v, want refused", id, d)
		}
	}
	// The other relay admits its own ticket and refuses this one's.
	env.send(otherStream, admitEvent(1, forBerlin))
	if d, err := env.recv(otherStream); err != nil || d.GetAdmitted().GetRequestId() != 1 {
		t.Errorf("berlin with its ticket: %+v %v", d, err)
	}
	env.send(otherStream, admitEvent(2, forRiyadh))
	if d, err := env.recv(otherStream); err != nil || d.GetRefused().GetRequestId() != 2 {
		t.Errorf("berlin with riyadh's ticket: %+v %v", d, err)
	}
}

func TestAttachVisibilityOnGeneration(t *testing.T) {
	env := newRelayCtlEnv(t)
	reg := env.register("riyadh-1")
	stream, _ := env.attach(reg.GetRelaySecret())
	env.waitOnline(1)
	aliceID, aliceKey := env.peer("markus", "alice")
	env.send(stream, admitEvent(1, env.ticket(aliceID)))
	d, err := env.recv(stream)
	if err != nil || len(d.GetAdmitted().GetVisibleKeys()) != 0 {
		t.Fatalf("alice alone: %+v %v", d, err)
	}
	gen := d.GetAdmitted().GetGeneration()

	// A device alice may not see changes the generation, not her keys:
	// nothing is sent. A device she may see produces one update.
	env.peer("lena", "carol")
	_, bobKey := env.peer("markus", "bob")
	d, err = env.recv(stream)
	if err != nil {
		t.Fatal(err)
	}
	vis := d.GetVisibility()
	if vis == nil || !bytes.Equal(vis.GetPeerKey(), aliceKey[:]) || len(vis.GetVisibleKeys()) != 1 || !bytes.Equal(vis.GetVisibleKeys()[0], bobKey[:]) || vis.GetGeneration() <= gen {
		t.Fatalf("after bob enrolled: %+v", d)
	}

	// Bob goes: alice's set shrinks again.
	if err := env.registry.Delete(context.Background(), env.admin, "bob"); err != nil {
		t.Fatal(err)
	}
	d, err = env.recv(stream)
	if err != nil || d.GetVisibility() == nil || len(d.GetVisibility().GetVisibleKeys()) != 0 {
		t.Fatalf("after bob was deleted: %+v %v", d, err)
	}

	// A closed session gets no more updates: the next directive is the
	// answer to the admission that follows, not a visibility push.
	env.send(stream, &thawrv1.RelayEvent{Event: &thawrv1.RelayEvent_Closed{Closed: &thawrv1.RelayClosed{PeerKey: aliceKey[:]}}})
	// Events are handled in order, so the refusal of a bad ticket sent
	// after it shows the close was processed before dave appears.
	env.send(stream, admitEvent(99, nil))
	if d, err := env.recv(stream); err != nil || d.GetRefused().GetRequestId() != 99 {
		t.Fatalf("marker admission: %+v %v", d, err)
	}
	daveID, _ := env.peer("markus", "dave")
	env.send(stream, admitEvent(2, env.ticket(daveID)))
	d, err = env.recv(stream)
	if err != nil || d.GetAdmitted().GetRequestId() != 2 {
		t.Fatalf("after alice's session closed: %+v %v", d, err)
	}
}

func TestAttachRevokeOnDelete(t *testing.T) {
	env := newRelayCtlEnv(t)
	ctx := context.Background()
	reg := env.register("riyadh-1")
	stream, _ := env.attach(reg.GetRelaySecret())
	env.waitOnline(1)
	aliceID, aliceKey := env.peer("markus", "alice")
	bobID, bobKey := env.peer("markus", "bob")
	env.send(stream, admitEvent(1, env.ticket(aliceID)))
	if d, err := env.recv(stream); err != nil || d.GetAdmitted() == nil {
		t.Fatalf("admit alice: %+v %v", d, err)
	}
	env.send(stream, admitEvent(2, env.ticket(bobID)))
	if d, err := env.recv(stream); err != nil || d.GetAdmitted() == nil {
		t.Fatalf("admit bob: %+v %v", d, err)
	}

	// Deleting alice revokes her session and shrinks bob's view.
	if err := env.registry.Delete(ctx, env.admin, "alice"); err != nil {
		t.Fatal(err)
	}
	var revoked, shrunk bool
	for i := 0; i < 2; i++ {
		d, err := env.recv(stream)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case d.GetRevoke() != nil && bytes.Equal(d.GetRevoke().GetPeerKey(), aliceKey[:]):
			revoked = true
		case d.GetVisibility() != nil && bytes.Equal(d.GetVisibility().GetPeerKey(), bobKey[:]) && len(d.GetVisibility().GetVisibleKeys()) == 0:
			shrunk = true
		default:
			t.Errorf("unexpected directive: %+v", d)
		}
	}
	if !revoked || !shrunk {
		t.Errorf("after deleting alice: revoked=%v bob's view shrunk=%v", revoked, shrunk)
	}

	// A rotated key revokes the session admitted under the old one,
	// also when the device is back with its new key before the netmap
	// change reached the stream: the relay gets the revocation and the
	// admission in either order, and each exactly once.
	newPriv, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newKey := newPriv.PublicKey()
	if _, err := env.registry.RotateKey(ctx, bobID, newKey.String(), nil); err != nil {
		t.Fatal(err)
	}
	env.send(stream, admitEvent(3, env.ticket(bobID)))
	var revokedOld, admittedNew bool
	for i := 0; i < 2; i++ {
		d, err := env.recv(stream)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case d.GetRevoke() != nil && bytes.Equal(d.GetRevoke().GetPeerKey(), bobKey[:]) && !revokedOld:
			revokedOld = true
		case d.GetAdmitted() != nil && d.GetAdmitted().GetRequestId() == 3 && bytes.Equal(d.GetAdmitted().GetPeerKey(), newKey[:]) && !admittedNew:
			admittedNew = true
		default:
			t.Errorf("unexpected directive: %+v", d)
		}
	}
	if !revokedOld || !admittedNew {
		t.Errorf("after bob rotated: old key revoked=%v admitted under the new key=%v", revokedOld, admittedNew)
	}
	// Nothing more follows: the next directive answers the next event.
	env.send(stream, admitEvent(4, nil))
	if d, err := env.recv(stream); err != nil || d.GetRefused().GetRequestId() != 4 {
		t.Errorf("after the rotation settled: %+v %v", d, err)
	}
}

// TestAttachEndsWhenReplacedOrDeleted: a second stream of the same
// relay ends the first without taking the relay offline, and deleting
// the relay ends its stream.
func TestAttachEndsWhenReplacedOrDeleted(t *testing.T) {
	env := newRelayCtlEnv(t)
	reg := env.register("riyadh-1")
	first, _ := env.attach(reg.GetRelaySecret())
	env.waitOnline(1)
	second, _ := env.attach(reg.GetRelaySecret())
	// The first stream notices at its next event or netmap change.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := first.Send(&thawrv1.RelayEvent{Event: &thawrv1.RelayEvent_Heartbeat{Heartbeat: &thawrv1.RelayHeartbeat{}}}); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the replaced stream is still accepting events")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := env.recv(first); status.Code(err) != codes.Aborted {
		t.Errorf("replaced stream ended with %v", err)
	}
	env.waitOnline(1)

	if _, err := env.relays.Delete(context.Background(), env.admin, "riyadh-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.recv(second); status.Code(err) != codes.Aborted {
		t.Errorf("stream of a deleted relay ended with %v", err)
	}
	stream, err := env.relay.Attach(authCtx(reg.GetRelaySecret()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.recv(stream); status.Code(err) != codes.Unauthenticated {
		t.Errorf("attach with a deleted relay's secret: %v", err)
	}
}

func TestNewGRPCRelayNeedsDeps(t *testing.T) {
	if _, err := NewGRPC(GRPCDeps{Enroller: &fakeEnroller{}, Hub: testHub(), Relay: &RelayDeps{}}); err == nil {
		t.Error("a relay service without its collaborators was accepted")
	}
}

// admitOps answers Admit with a fixed peer; nothing else is called.
type admitOps struct {
	RelayOps
	peer store.Peer
}

func (o admitOps) Admit(context.Context, string, []byte) (store.Peer, error) { return o.peer, nil }

type emptyNetMaps struct{}

func (emptyNetMaps) Build(context.Context, string) (control.NetMap, error) {
	return control.NetMap{Generation: 5}, nil
}

// directiveLog records what a handler sends.
type directiveLog struct {
	grpc.BidiStreamingServer[thawrv1.RelayEvent, thawrv1.RelayDirective]
	sent []*thawrv1.RelayDirective
}

func (l *directiveLog) Send(d *thawrv1.RelayDirective) error {
	l.sent = append(l.sent, d)
	return nil
}

// TestAdmitRevokesReplacedKey pins the order the stream test cannot
// force: a device is admitted under a new key while the session map
// still holds its old one, because the netmap change has not reached
// the stream yet. The old key is revoked first, then the new admitted.
func TestAdmitRevokesReplacedKey(t *testing.T) {
	oldPriv, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newPriv, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	oldKey, newKey := oldPriv.PublicKey(), newPriv.PublicKey()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &relayControlServer{deps: RelayDeps{
		Relays:  admitOps{peer: store.Peer{ID: "p_bob", PublicKey: newKey.String()}},
		NetMaps: emptyNetMaps{}, Logger: quiet,
	}}
	sessions := map[string]*relaySession{"p_bob": {peerID: "p_bob", key: oldKey}}
	out := &directiveLog{}
	admit := &thawrv1.RelayAdmit{RequestId: 1, Ticket: []byte("ticket")}
	if err := srv.admit(context.Background(), out, "rl_1", admit, sessions, quiet); err != nil {
		t.Fatal(err)
	}
	if len(out.sent) != 2 || !bytes.Equal(out.sent[0].GetRevoke().GetPeerKey(), oldKey[:]) ||
		!bytes.Equal(out.sent[1].GetAdmitted().GetPeerKey(), newKey[:]) {
		t.Fatalf("directives: %+v", out.sent)
	}
	if sessions["p_bob"].key != newKey {
		t.Error("the session still holds the old key")
	}

	// The same key again revokes nothing.
	out.sent = nil
	admit.RequestId = 2
	if err := srv.admit(context.Background(), out, "rl_1", admit, sessions, quiet); err != nil {
		t.Fatal(err)
	}
	if len(out.sent) != 1 || out.sent[0].GetAdmitted().GetRequestId() != 2 {
		t.Errorf("re-admission under the same key: %+v", out.sent)
	}
}

// TestSyncListsRelayNodes: a client that says relay_nodes gets the
// online relays with a ticket each relay's server check accepts; one
// that does not gets none, and the tickets it held stop working.
func TestSyncListsRelayNodes(t *testing.T) {
	env := newRelayCtlEnv(t)
	ctx := context.Background()
	reg := env.register("riyadh-1")
	relayStream, _ := env.attach(reg.GetRelaySecret())
	env.waitOnline(1)

	tok, err := env.tokens.Create(ctx, env.admin, control.TokenRequest{OwnerName: "markus", Kind: "human"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey()
	enrolled, err := env.control.Enroll(ctx, &thawrv1.EnrollRequest{Token: tok.Secret, PublicKey: pub.String(), Hostname: "alice", RelayNodes: true})
	if err != nil {
		t.Fatal(err)
	}

	syncCtx, cancel := context.WithCancel(authCtx(enrolled.GetNodeSecret()))
	stream, err := env.control.Sync(syncCtx, &thawrv1.SyncRequest{RelayNodes: true})
	if err != nil {
		t.Fatal(err)
	}
	nm, err := recvMap(t, stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.GetRelays()) != 1 {
		t.Fatalf("relays in the netmap: %+v", nm.GetRelays())
	}
	node := nm.GetRelays()[0]
	if node.GetId() != reg.GetRelayId() || node.GetName() != "riyadh-1" || node.GetUrl() != restRelayURL || node.GetTlsFingerprint() != restRelayFP ||
		len(node.GetTicket()) != control.TicketLen || node.GetTicketExpires() <= time.Now().Unix() {
		t.Errorf("relay node: id=%q name=%q url=%q expires=%d", node.GetId(), node.GetName(), node.GetUrl(), node.GetTicketExpires())
	}
	env.send(relayStream, admitEvent(1, node.GetTicket()))
	if d, err := env.recv(relayStream); err != nil || !bytes.Equal(d.GetAdmitted().GetPeerKey(), pub[:]) {
		t.Fatalf("the netmap's ticket at the relay: %+v %v", d, err)
	}
	cancel()

	// The same device with a client that does not know relay nodes.
	old, err := env.control.Sync(authCtx(enrolled.GetNodeSecret()), &thawrv1.SyncRequest{})
	if err != nil {
		t.Fatal(err)
	}
	nm, err = recvMap(t, old)
	if err != nil || len(nm.GetRelays()) != 0 {
		t.Fatalf("netmap without relay_nodes: %+v %v", nm.GetRelays(), err)
	}
	env.send(relayStream, admitEvent(2, node.GetTicket()))
	if d, err := env.recv(relayStream); err != nil || d.GetRefused().GetRequestId() != 2 {
		t.Errorf("the old ticket after the downgrade: %+v %v", d, err)
	}
}

// failingCapability is a registry whose relay capability write fails.
type failingCapability struct{ PeerOps }

func (failingCapability) SetRelayCapable(context.Context, string, bool) (bool, error) {
	return false, errors.New("disk full")
}

// TestSyncEndsWhenCapabilityNotRecorded: the flag decides who holds
// tickets, so a sync that could not record it sends no netmap at all
// and the client comes back.
func TestSyncEndsWhenCapabilityNotRecorded(t *testing.T) {
	env := newRelayCtlEnvWith(t, func(p PeerOps) PeerOps { return failingCapability{p} })
	ctx := context.Background()
	tok, err := env.tokens.Create(ctx, env.admin, control.TokenRequest{OwnerName: "markus", Kind: "human"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := env.control.Enroll(ctx, &thawrv1.EnrollRequest{Token: tok.Secret, PublicKey: key.PublicKey().String(), Hostname: "alice", RelayNodes: true})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := env.control.Sync(authCtx(enrolled.GetNodeSecret()), &thawrv1.SyncRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if nm, err := recvMap(t, stream); status.Code(err) != codes.Unavailable {
		t.Errorf("sync with a failed capability write: %+v %v", nm, err)
	}
}
