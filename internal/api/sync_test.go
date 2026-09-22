package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	thawrv1 "github.com/thedatadudech/thawr/internal/api/proto/thawr/v1"
	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/store"
	"github.com/thedatadudech/thawr/internal/wg"
)

// testHubKey is a fixed, valid hub public key (spec 012 signs it, so
// a placeholder string no longer does).
const testHubKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="

// syncEnv is a full control plane on a temp store behind bufconn.
type syncEnv struct {
	t        *testing.T
	st       *store.Store
	hub      *control.Hub
	registry *control.Registry
	tokens   *control.Tokens
	client   thawrv1.ControlClient
	admin    control.Principal
	lock     *control.LockService
	routes   *control.RoutesService
}

func newSyncEnv(t *testing.T) *syncEnv {
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
	hub, err := control.NewHub(ctx, st, now, quiet, control.HubOptions{Coalesce: 10 * time.Millisecond, KeepaliveInterval: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	overlay := netip.MustParsePrefix("100.64.0.0/10")
	lockSvc := control.NewLockService(st, now, quiet, testHubKey).WithNotifier(hub)
	registry := control.NewRegistry(st, quiet).WithNotifier(hub).WithLock(lockSvc)
	enroller := control.NewEnroller(st, now, quiet, overlay, "").WithNotifier(hub)
	routesSvc := control.NewRoutesService(st, quiet, now, overlay).WithNotifier(hub)
	endpoints := control.NewEndpointTable(now)
	hubInfo := control.HubConfig{PublicKey: testHubKey, Endpoint: "vpn:51820", Address: netip.MustParseAddr("100.64.0.1"), Overlay: overlay, STUNAddrs: []string{"vpn:3478", "vpn:3479"}}
	builder := control.NewNetMapBuilder(st, control.OwnerVisibility{}, endpoints, hub, hubInfo, hub.Generation)
	srv, err := NewGRPC(GRPCDeps{
		Enroller: enroller, Hub: HubInfo{PublicKey: testHubKey, Endpoint: "vpn:51820", Overlay: overlay}, Logger: quiet,
		NodeAuth: registry, NetMaps: builder, Sync: hub, Peers: registry, Endpoints: endpoints, Paths: control.NewPathTable(now),
		Lock: lockSvc, Routes: routesSvc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &syncEnv{t: t, st: st, hub: hub, registry: registry, tokens: control.NewTokens(st, now, quiet), lock: lockSvc, routes: routesSvc,
		client: bufconnClient(t, srv), admin: control.Principal{UserID: admin.ID, Name: admin.Name, Role: admin.Role}}
}

// enrol registers a peer for owner and returns its id and node secret.
func (e *syncEnv) enrol(hostname string) (string, string) {
	e.t.Helper()
	ctx := context.Background()
	tok, err := e.tokens.Create(ctx, e.admin, control.TokenRequest{OwnerName: "markus", Kind: "human"})
	if err != nil {
		e.t.Fatal(err)
	}
	key, _ := wg.GenerateKey()
	resp, err := e.client.Enroll(ctx, &thawrv1.EnrollRequest{Token: tok.Secret, PublicKey: key.PublicKey().String(), Hostname: hostname, ClientVersion: "0.1.0"})
	if err != nil {
		e.t.Fatalf("enroll %s: %v", hostname, err)
	}
	return resp.GetPeerId(), resp.GetNodeSecret()
}

func authCtx(secret string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+secret)
}

func recvMap(t *testing.T, stream grpc.ServerStreamingClient[thawrv1.NetMap]) (*thawrv1.NetMap, error) {
	const wait = 2 * time.Second
	t.Helper()
	type result struct {
		nm  *thawrv1.NetMap
		err error
	}
	ch := make(chan result, 1)
	go func() {
		nm, err := stream.Recv()
		ch <- result{nm, err}
	}()
	select {
	case r := <-ch:
		return r.nm, r.err
	case <-time.After(wait):
		t.Fatalf("no netmap within %s", wait)
		return nil, nil
	}
}

func TestSyncRequiresAuth(t *testing.T) {
	env := newSyncEnv(t)
	stream, err := env.client.Sync(context.Background(), &thawrv1.SyncRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no secret: %v", err)
	}
	stream, _ = env.client.Sync(authCtx("wrong"), &thawrv1.SyncRequest{})
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Errorf("wrong secret: %v", err)
	}
	if _, err := env.client.RotateKey(context.Background(), &thawrv1.RotateKeyRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("unary without secret: %v", err)
	}
}

func TestSyncStreamsOnChange(t *testing.T) {
	env := newSyncEnv(t)
	aID, aSecret := env.enrol("a")
	stream, err := env.client.Sync(authCtx(aSecret), &thawrv1.SyncRequest{ClientVersion: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := recvMap(t, stream)
	if err != nil {
		t.Fatalf("first map: %v", err)
	}
	if first.GetSelf().GetId() != aID || first.GetSelf().GetIpv4() != "100.64.0.2" || len(first.GetPeers()) != 0 || first.GetHub().GetPublicKey() != testHubKey || first.GetKeepalive() ||
		len(first.GetSelf().GetStunAddrs()) != 2 || first.GetSelf().GetStunAddrs()[0] != "vpn:3478" {
		t.Errorf("first map: %+v", first)
	}
	if !env.hub.Online(aID) {
		t.Error("peer not online while streaming")
	}
	if p, err := env.st.Peers().GetByID(context.Background(), aID); err != nil || p.ClientVersion != "0.1.0" {
		t.Errorf("client version after sync: %+v %v", p, err)
	}

	bID, bSecret := env.enrol("b")
	var withB *thawrv1.NetMap
	for i := 0; i < 5; i++ {
		nm, err := recvMap(t, stream)
		if err != nil {
			t.Fatal(err)
		}
		if len(nm.GetPeers()) == 1 {
			withB = nm
			break
		}
	}
	if withB == nil || withB.GetPeers()[0].GetId() != bID || withB.GetPeers()[0].GetOnline() {
		t.Fatalf("map after enrolling b: %+v", withB)
	}
	if withB.GetGeneration() <= first.GetGeneration() {
		t.Errorf("generation did not advance: %d -> %d", first.GetGeneration(), withB.GetGeneration())
	}

	// b reports endpoints: a gets them without a persistent change.
	if _, err := env.client.ReportEndpoints(authCtx(bSecret), &thawrv1.EndpointReport{
		Endpoints: []*thawrv1.Endpoint{{Addr: "192.168.1.9:41820", Kind: thawrv1.EndpointKind_ENDPOINT_KIND_LOCAL}}, ListenPort: 41820}); err != nil {
		t.Fatal(err)
	}
	var withEP *thawrv1.NetMap
	for i := 0; i < 5; i++ {
		nm, err := recvMap(t, stream)
		if err != nil {
			t.Fatal(err)
		}
		if len(nm.GetPeers()) == 1 && len(nm.GetPeers()[0].GetEndpoints()) == 1 {
			withEP = nm
			break
		}
	}
	if withEP == nil || withEP.GetPeers()[0].GetEndpoints()[0].GetAddr() != "192.168.1.9:41820" {
		t.Fatalf("endpoints not delivered: %+v", withEP)
	}

	// Keepalives arrive with the flag set.
	sawKeepalive := false
	for i := 0; i < 5 && !sawKeepalive; i++ {
		nm, err := recvMap(t, stream)
		if err != nil {
			t.Fatal(err)
		}
		sawKeepalive = nm.GetKeepalive()
	}
	if !sawKeepalive {
		t.Error("no keepalive netmap received")
	}
}

func TestSyncEndsWhenPeerDeleted(t *testing.T) {
	env := newSyncEnv(t)
	_, aSecret := env.enrol("a")
	stream, err := env.client.Sync(authCtx(aSecret), &thawrv1.SyncRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recvMap(t, stream); err != nil {
		t.Fatal(err)
	}
	if err := env.registry.Delete(context.Background(), env.admin, "a"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := recvMap(t, stream)
		if err != nil {
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("stream ended with %v, want PermissionDenied", err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream still open 5s after deletion")
		}
	}
	if _, err := env.client.RotateKey(authCtx(aSecret), &thawrv1.RotateKeyRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("deleted peer's secret still accepted: %v", err)
	}
}

func TestReportEndpointsValidation(t *testing.T) {
	env := newSyncEnv(t)
	_, secret := env.enrol("a")
	bad := []*thawrv1.EndpointReport{
		{Endpoints: []*thawrv1.Endpoint{{Addr: "nope", Kind: thawrv1.EndpointKind_ENDPOINT_KIND_LOCAL}}},
		{Endpoints: []*thawrv1.Endpoint{{Addr: "127.0.0.1:5", Kind: thawrv1.EndpointKind_ENDPOINT_KIND_LOCAL}}},
		{Endpoints: []*thawrv1.Endpoint{{Addr: "10.0.0.1:5"}}},
		{ListenPort: 70000},
	}
	for _, r := range bad {
		if _, err := env.client.ReportEndpoints(authCtx(secret), r); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%v: %v", r, err)
		}
	}
	if _, err := env.client.ReportPath(authCtx(secret), &thawrv1.PathReport{Paths: []*thawrv1.PathState{{PeerId: "x", State: "teleport"}}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad path state: %v", err)
	}
	if _, err := env.client.ReportPath(authCtx(secret), &thawrv1.PathReport{Paths: []*thawrv1.PathState{{PeerId: "x", State: "direct", Endpoint: "1.2.3.4:5"}}}); err != nil {
		t.Errorf("good path: %v", err)
	}
}

func TestRotateKeyAndLeave(t *testing.T) {
	env := newSyncEnv(t)
	aID, aSecret := env.enrol("a")
	_, bSecret := env.enrol("b")
	stream, err := env.client.Sync(authCtx(bSecret), &thawrv1.SyncRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recvMap(t, stream); err != nil {
		t.Fatal(err)
	}
	newKey, _ := wg.GenerateKey()
	resp, err := env.client.RotateKey(authCtx(aSecret), &thawrv1.RotateKeyRequest{NewPublicKey: newKey.PublicKey().String()})
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if resp.GetGeneration() == 0 {
		t.Error("no generation returned")
	}
	var seen bool
	for i := 0; i < 5 && !seen; i++ {
		nm, err := recvMap(t, stream)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range nm.GetPeers() {
			if p.GetId() == aID && p.GetPublicKey() == newKey.PublicKey().String() {
				seen = true
			}
		}
	}
	if !seen {
		t.Error("b never received a's new key")
	}
	if _, err := env.client.RotateKey(authCtx(aSecret), &thawrv1.RotateKeyRequest{NewPublicKey: "junk"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("junk key: %v", err)
	}
	if _, err := env.client.Leave(authCtx(aSecret), &thawrv1.Empty{}); err != nil {
		t.Fatalf("Leave: %v", err)
	}
	if _, err := env.st.Peers().GetByID(context.Background(), aID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("peer still present after Leave: %v", err)
	}
	var _ net.Conn
	_ = bufconn.Listen
	_ = insecure.NewCredentials
}
