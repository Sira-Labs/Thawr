package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/thedatadudech/thawr/internal/api"
	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/control/path"
	"github.com/thedatadudech/thawr/internal/relay"
	"github.com/thedatadudech/thawr/internal/store"
	"github.com/thedatadudech/thawr/internal/stun"
	"github.com/thedatadudech/thawr/internal/wg"
	"github.com/thedatadudech/thawr/internal/wg/wgtest"
)

// controlPlane is a real server-side control plane over a TLS HTTP/2
// test server, enough for the daemon to enrol and sync.
type controlPlane struct {
	t         *testing.T
	st        *store.Store
	hub       *control.Hub
	registry  *control.Registry
	tokens    *control.Tokens
	endpoints *control.EndpointTable
	paths     *control.PathTable
	relay     *relay.Server
	lock      *control.LockService
	admin     control.Principal
	ts        *httptest.Server
	fp        string
	hubKey    wg.Key
}

// cpOptions tune the test control plane.
type cpOptions struct {
	visibility control.Visibility
}

func newControlPlane(t *testing.T, mods ...func(*cpOptions)) *controlPlane {
	t.Helper()
	cpo := cpOptions{visibility: control.OwnerVisibility{}}
	for _, m := range mods {
		m(&cpo)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	users, err := control.NewUsers(st, time.Now, quiet)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := users.Create(ctx, control.LocalAdmin, "markus", store.RoleAdmin, "adminpassword")
	if err != nil {
		t.Fatal(err)
	}
	hub, err := control.NewHub(ctx, st, time.Now, quiet, control.HubOptions{Coalesce: 10 * time.Millisecond, KeepaliveInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	overlay := netip.MustParsePrefix("100.64.0.0/10")
	hubKey, _ := wg.GenerateKey()
	lockSvc := control.NewLockService(st, time.Now, quiet, hubKey.PublicKey().String()).WithNotifier(hub)
	registry := control.NewRegistry(st, quiet).WithNotifier(hub).WithLock(lockSvc)
	enroller := control.NewEnroller(st, time.Now, quiet, overlay, "").WithNotifier(hub)
	endpoints := control.NewEndpointTable(time.Now)
	paths := control.NewPathTable(time.Now)
	hubCfg := control.HubConfig{PublicKey: hubKey.PublicKey().String(), Endpoint: "127.0.0.1:51820", Address: netip.MustParseAddr("100.64.0.1"), Overlay: overlay,
		STUNAddrs: []string{"127.0.0.1:3478", "127.0.0.1:3479"}}
	builder := control.NewNetMapBuilder(st, cpo.visibility, endpoints, hub, hubCfg, hub.Generation)
	grpcSrv, err := api.NewGRPC(api.GRPCDeps{
		Enroller: enroller, Hub: api.HubInfo{PublicKey: hubCfg.PublicKey, Endpoint: hubCfg.Endpoint, Overlay: overlay}, Logger: quiet,
		NodeAuth: registry, NetMaps: builder, Sync: hub, Peers: registry, Endpoints: endpoints, Paths: paths, Version: "v0.9.0", Lock: lockSvc,
	})
	if err != nil {
		t.Fatal(err)
	}
	relaySrv := relay.NewServer(keyVisibility{control.NewKeyVisibility(st, cpo.visibility, hub.Generation)}, relay.ServerOptions{Logger: quiet})
	t.Cleanup(relaySrv.Close)
	rest, err := api.NewREST(api.RESTDeps{Status: statusStub{}, UI: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("x")}}, Logger: quiet, NodeAuth: registry, Relay: relaySrv})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(api.Combine(grpcSrv, rest))
	ts.EnableHTTP2 = true
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return &controlPlane{t: t, st: st, hub: hub, registry: registry, tokens: control.NewTokens(st, time.Now, quiet), endpoints: endpoints, paths: paths, relay: relaySrv, lock: lockSvc,
		admin: control.Principal{UserID: admin.ID, Name: admin.Name, Role: admin.Role}, ts: ts, fp: Fingerprint(ts.Certificate().Raw), hubKey: hubKey}
}

// keyVisibility adapts control.KeyVisibility to the relay's key type.
type keyVisibility struct {
	kv *control.KeyVisibility
}

func (v keyVisibility) Visible(ctx context.Context, src, dst relay.Key) (bool, error) {
	return v.kv.Visible(ctx, wg.Key(src).String(), wg.Key(dst).String())
}

// enrol registers a device into dir and returns its state.
func (cp *controlPlane) enrol(dir, host string) State {
	cp.t.Helper()
	return cp.enrolWith(dir, host, nil)
}

// enrolWith is enrol with the options adjusted first.
func (cp *controlPlane) enrolWith(dir, host string, mod func(*Options)) State {
	cp.t.Helper()
	tok, err := cp.tokens.Create(context.Background(), cp.admin, control.TokenRequest{OwnerName: "markus", Kind: "human"})
	if err != nil {
		cp.t.Fatal(err)
	}
	opts := Options{Server: cp.ts.URL, Token: tok.Secret, Fingerprint: cp.fp, StateDir: dir, Hostname: host, Version: "0.1.0"}
	if mod != nil {
		mod(&opts)
	}
	st, err := Enroll(context.Background(), opts)
	if err != nil {
		cp.t.Fatalf("enrol %s: %v", host, err)
	}
	return st
}

// shortSocket returns a socket path short enough for every platform's
// Unix socket limit (macOS temp dirs are long).
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "th")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

// fixedSTUN scripts reflexive discovery: every server maps to mapped.
func fixedSTUN(mapped string, symmetric bool) STUNFunc {
	return func(_ context.Context, _ wg.Device, servers []netip.AddrPort, _ time.Duration) (stun.Result, bool, error) {
		res := stun.Result{Symmetric: symmetric}
		for range servers {
			res.Mapped = append(res.Mapped, netip.MustParseAddrPort(mapped))
		}
		return res, false, nil
	}
}

func startDaemon(t *testing.T, dir string, mods ...func(*DaemonOptions)) (*Daemon, *wgtest.Fake, func()) {
	t.Helper()
	fake := wgtest.New("thawr0")
	socket := shortSocket(t)
	logOut := io.Discard
	if os.Getenv("THAWR_TEST_LOG") != "" {
		logOut = os.Stderr
	}
	opts := DaemonOptions{
		StateDir: dir, Socket: socket, Interface: "thawr0",
		OpenDevice: func(context.Context, wg.Options) (wg.Device, error) { return fake, nil },
		Logger:     slog.New(slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: slog.LevelDebug})), Version: "0.1.0",
		MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond, EndpointInterval: time.Hour, LocalPoll: time.Hour,
		Endpoints: func(port int, _ string) []netip.AddrPort {
			return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(port))}
		},
		STUN:      fixedSTUN("203.0.113.5:4444", false),
		Path:      path.Options{ProbeWindow: 100 * time.Millisecond, RetryAfter: 500 * time.Millisecond},
		ProbeTick: 20 * time.Millisecond, IdleTick: 50 * time.Millisecond,
		Trigger: func(context.Context, string, netip.Addr, netip.Addr) error { return nil },
		Relay:   relay.ClientOptions{MinBackoff: 20 * time.Millisecond, MaxBackoff: 100 * time.Millisecond, ReleaseDelay: 20 * time.Millisecond, IdleTimeout: 200 * time.Millisecond},
		// The fake device carries no address to bind; tests that need
		// the resolver inject a loopback listener.
		DNS: DNSOptions{Mode: DNSServe, Listen: func(context.Context, netip.AddrPort) (net.PacketConn, net.Listener, error) {
			return nil, nil, errors.New("no overlay address in tests")
		}},
	}
	for _, m := range mods {
		m(&opts)
	}
	d, err := NewDaemon(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	return d, fake, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	}
}

func waitApplied(t *testing.T, d *Daemon, cond func(NetMap) bool) NetMap {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case nm := <-d.Applied():
			if cond(nm) {
				return nm
			}
		case <-deadline:
			t.Fatal("no matching netmap within 5s")
		}
	}
}

func TestBuildConfig(t *testing.T) {
	key, _ := wg.GenerateKey()
	hubKey, _ := wg.GenerateKey()
	peerKey, _ := wg.GenerateKey()
	nm := NetMap{
		SelfIPv4: "100.64.0.7",
		Hub:      HubPeer{PublicKey: hubKey.PublicKey().String(), Endpoint: "203.0.113.1:51820", AllowedIPs: []string{"100.64.0.1/32", "100.64.0.21/32"}},
		Peers: []Peer{{Name: "nas", PublicKey: peerKey.PublicKey().String(), IPv4: "100.64.0.3", Endpoints: []Endpoint{{Addr: "192.168.1.5:41820", Kind: KindLocal}, {Addr: "10.0.0.5:41820", Kind: KindLocal}},
			AllowedIPs: []string{"100.64.0.3/32"}, Keepalive: true}},
	}
	cfg, err := BuildConfig(nm, key, 41820, netip.MustParsePrefix("100.64.0.0/10"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PrivateKey != key || cfg.ListenPort != 41820 || len(cfg.Addresses) != 1 || cfg.Addresses[0].String() != "100.64.0.7/10" {
		t.Errorf("interface config: %+v", cfg)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("peers: %d", len(cfg.Peers))
	}
	hub := cfg.Peers[0]
	if hub.PublicKey != hubKey.PublicKey() || hub.Endpoint.String() != "203.0.113.1:51820" || hub.Keepalive != PeerKeepalive || len(hub.AllowedIPs) != 2 {
		t.Errorf("hub: %+v", hub)
	}
	nas := cfg.Peers[1]
	if nas.PublicKey != peerKey.PublicKey() || nas.Endpoint.IsValid() || nas.Keepalive != PeerKeepalive || nas.AllowedIPs[0].String() != "100.64.0.3/32" {
		t.Errorf("nas: %+v (the prober owns mesh endpoints)", nas)
	}
	if c := nm.Peers[0].Candidates(); len(c) != 2 || c[0].Kind != control.EndpointLocal {
		t.Errorf("candidates: %+v", c)
	}
	if _, err := BuildConfig(NetMap{SelfIPv4: "bad"}, key, 1, netip.MustParsePrefix("100.64.0.0/10")); err == nil {
		t.Error("bad self address accepted")
	}
	nm.Peers[0].PublicKey = "junk"
	if _, err := BuildConfig(nm, key, 1, netip.MustParsePrefix("100.64.0.0/10")); err == nil {
		t.Error("bad peer key accepted")
	}
}

func TestDaemonSyncAppliesAndCaches(t *testing.T) {
	cp := newControlPlane(t)
	dirA, dirB := t.TempDir(), t.TempDir()
	cp.enrol(dirA, "a")
	d, fake, stop := startDaemon(t, dirA)
	defer stop()

	first := waitApplied(t, d, func(nm NetMap) bool { return nm.Hub.PublicKey != "" })
	if first.SelfName != "a" || first.Hub.PublicKey != cp.hubKey.PublicKey().String() || len(first.Peers) != 0 {
		t.Errorf("first map: %+v", first)
	}
	last, _ := fake.Last()
	if len(last.Peers) != 1 || last.Peers[0].PublicKey != cp.hubKey.PublicKey() || last.Addresses[0].String() != "100.64.0.2/10" {
		t.Errorf("device after first map: %+v", last)
	}

	stB := cp.enrol(dirB, "b")
	withB := waitApplied(t, d, func(nm NetMap) bool { return len(nm.Peers) == 1 })
	if withB.Peers[0].Name != "b" || withB.Peers[0].IPv4 != stB.IPv4 {
		t.Errorf("map with b: %+v", withB.Peers)
	}
	last, _ = fake.Last()
	if len(last.Peers) != 2 {
		t.Errorf("device peers after b: %d", len(last.Peers))
	}
	cached, ok, err := LoadNetMap(dirA)
	if err != nil || !ok || cached.Generation != withB.Generation {
		t.Errorf("cache: ok=%v gen=%d err=%v", ok, cached.Generation, err)
	}
	if fi, _ := os.Stat(filepath.Join(dirA, NetMapFile)); runtime.GOOS != "windows" && fi != nil && fi.Mode().Perm() != 0o600 {
		t.Errorf("netmap cache mode %o", fi.Mode().Perm())
	}

	// Status over the socket.
	lc := NewLocalClient(d.opts.Socket)
	st, err := lc.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Server.State != ServerConnected || st.Self.Name != "a" || st.Self.Kind != "human" || len(st.Peers) != 1 || st.Peers[0].Name != "b" || st.Hub == nil || st.WireGuard.Backend != "fake" || st.Server.Version != "v0.9.0" {
		t.Errorf("status: %+v", st)
	}

	// Peer removal reaches the device within 5 s.
	start := time.Now()
	if err := cp.registry.Delete(context.Background(), cp.admin, "b"); err != nil {
		t.Fatal(err)
	}
	waitApplied(t, d, func(nm NetMap) bool { return len(nm.Peers) == 0 })
	if time.Since(start) > 5*time.Second {
		t.Error("removal took longer than 5s")
	}
	last, _ = fake.Last()
	if len(last.Peers) != 1 {
		t.Errorf("device still has removed peer: %+v", last.Peers)
	}
}

func TestDaemonAppliesCachedNetMapFirst(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	st := cp.enrol(dir, "a")
	cached := NetMap{Generation: 9, SelfID: st.PeerID, SelfName: st.Name, SelfIPv4: st.IPv4, Overlay: st.OverlayCIDR,
		Hub: HubPeer{PublicKey: cp.hubKey.PublicKey().String(), Endpoint: "127.0.0.1:51820", AllowedIPs: []string{"100.64.0.1/32"}}}
	if err := SaveNetMap(dir, cached); err != nil {
		t.Fatal(err)
	}
	cp.ts.Close() // server unreachable
	d, fake, stop := startDaemon(t, dir)
	defer stop()
	nm := waitApplied(t, d, func(nm NetMap) bool { return nm.Generation == 9 })
	if nm.Hub.PublicKey != cached.Hub.PublicKey {
		t.Errorf("cached map not applied: %+v", nm)
	}
	if cfgs := len(fake.Snapshots()); cfgs < 1 {
		t.Errorf("device not configured from cache")
	}
	time.Sleep(300 * time.Millisecond)
	lc := NewLocalClient(d.opts.Socket)
	status, err := lc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Server.State != ServerCached || status.Server.LastError == "" || status.Server.Generation != 9 {
		t.Errorf("status while offline: %+v", status)
	}
}

func TestDaemonRotateKeyAndDown(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	st := cp.enrol(dir, "a")
	d, fake, stop := startDaemon(t, dir)
	waitApplied(t, d, func(nm NetMap) bool { return nm.Hub.PublicKey != "" })
	oldKey, _ := LoadKey(dir)

	lc := NewLocalClient(d.opts.Socket)
	if err := lc.RotateKey(context.Background()); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	newKey, _ := LoadKey(dir)
	if newKey == oldKey {
		t.Error("key file not rotated")
	}
	stored, _ := cp.st.Peers().GetByID(context.Background(), st.PeerID)
	if stored.PublicKey != newKey.PublicKey().String() {
		t.Error("server does not have the new key")
	}
	last, _ := fake.Last()
	if last.PrivateKey != newKey {
		t.Error("device not reconfigured with the new key")
	}

	if err := lc.Down(context.Background()); err != nil {
		t.Fatalf("down: %v", err)
	}
	stop()
	if _, err := os.Stat(d.opts.Socket); !errors.Is(err, os.ErrNotExist) {
		t.Error("socket not removed after stop")
	}
	if !fake.Closed() {
		t.Error("device not closed after stop")
	}
}

func TestDaemonRemovedPeerBacksOff(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	cp.enrol(dir, "a")
	d, _, stop := startDaemon(t, dir)
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return nm.Hub.PublicKey != "" })
	if err := cp.registry.Delete(context.Background(), cp.admin, "a"); err != nil {
		t.Fatal(err)
	}
	lc := NewLocalClient(d.opts.Socket)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := lc.Status(context.Background())
		if err == nil && st.Server.State == ServerCached && st.Server.LastError != "" && st.Server.Attempt > 0 && st.Server.NextRetryAt != nil && st.Server.UnreachableSince != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon did not report removal: %+v", st)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestBackoffDelay(t *testing.T) {
	minD, maxD := time.Second, 60*time.Second
	prev := time.Duration(0)
	for attempt := 1; attempt <= 10; attempt++ {
		d := backoffDelay(attempt, minD, maxD)
		if d < minD || d > maxD {
			t.Errorf("attempt %d: %s out of bounds", attempt, d)
		}
		if attempt <= 6 && d < prev/2 {
			t.Errorf("attempt %d: %s not growing from %s", attempt, d, prev)
		}
		prev = d
	}
	if d := backoffDelay(20, minD, maxD); d < 48*time.Second {
		t.Errorf("late attempt %s should sit at the cap", d)
	}
}

func TestNewDaemonRequiresEnrollment(t *testing.T) {
	if _, err := NewDaemon(DaemonOptions{StateDir: t.TempDir()}); !errors.Is(err, ErrNotEnrolled) {
		t.Errorf("got %v, want ErrNotEnrolled", err)
	}
}

func TestLocalEndpoints(t *testing.T) {
	eps := LocalEndpoints(41820, "")
	for _, e := range eps {
		if e.Port() != 41820 || e.Addr().IsLoopback() || !e.Addr().Is4() {
			t.Errorf("bad candidate %s", e)
		}
	}
	var _ http.Handler = http.NewServeMux()
}

// TestDaemonHoldsChangedKey: a peer whose key changes on the server is
// held out of the device, DNS and paths until trusted over the socket.
func TestDaemonHoldsChangedKey(t *testing.T) {
	cp := newControlPlane(t)
	dirA, dirB := t.TempDir(), t.TempDir()
	cp.enrol(dirA, "a")
	stB := cp.enrol(dirB, "b")
	d, fake, stop := startDaemon(t, dirA)
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return len(nm.Peers) == 1 })
	last, _ := fake.Last()
	if len(last.Peers) != 2 {
		t.Fatalf("device peers before rotation: %d", len(last.Peers))
	}

	rotated, _ := wg.GenerateKey()
	if _, err := cp.registry.RotateKey(context.Background(), stB.PeerID, rotated.PublicKey().String(), nil); err != nil {
		t.Fatal(err)
	}
	waitApplied(t, d, func(nm NetMap) bool { return len(nm.Peers) == 0 })
	last, _ = fake.Last()
	if len(last.Peers) != 1 {
		t.Errorf("held peer still on the device: %+v", last.Peers)
	}
	lc := NewLocalClient(d.opts.Socket)
	st, err := lc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Held) != 1 || st.Held[0].Name != "b" || st.Held[0].OfferedKey != rotated.PublicKey().String() || st.Held[0].IPv4 != stB.IPv4 {
		t.Fatalf("held: %+v", st.Held)
	}
	if len(st.Peers) != 1 || st.Peers[0].Path != PathKeyChanged || st.Peers[0].PublicKey != rotated.PublicKey().String() {
		t.Errorf("peer row: %+v", st.Peers)
	}
	if _, err := d.Ping(context.Background(), "b"); !errors.Is(err, ErrUnknownPeer) {
		t.Errorf("ping of a held peer: %v", err)
	}
	for _, e := range d.dnsEntries() {
		if e.Name == "b" {
			t.Error("held peer still resolves")
		}
	}
	if _, err := lc.Trust(context.Background(), "nas"); err == nil {
		t.Error("trusting an unknown name succeeded")
	} else if le := new(LocalError); !errors.As(err, &le) || le.Status != http.StatusNotFound {
		t.Errorf("unknown name: %v", err)
	}

	res, err := lc.Trust(context.Background(), "b.thawr")
	if err != nil || len(res.Trusted) != 1 || res.Trusted[0].Name != "b" {
		t.Fatalf("trust: %+v err=%v", res, err)
	}
	last, _ = fake.Last()
	if len(last.Peers) != 2 || (last.Peers[1].PublicKey != rotated.PublicKey() && last.Peers[0].PublicKey != rotated.PublicKey()) {
		t.Errorf("device after trust: %+v", last.Peers)
	}
	if st, _ = lc.Status(context.Background()); len(st.Held) != 0 || len(st.Peers) != 1 || st.Peers[0].Path == PathKeyChanged {
		t.Errorf("status after trust: held=%v peers=%+v", st.Held, st.Peers)
	}
	pins, err := LoadPins(dirA)
	if err != nil || pins.peers["b"].Key != rotated.PublicKey().String() || pins.peers["b"].ID != stB.PeerID {
		t.Errorf("pins after trust: %+v err=%v", pins.peers, err)
	}
	if _, err := lc.Trust(context.Background(), "all"); err == nil {
		t.Error("trust --all with nothing held succeeded")
	}
}

// TestDaemonHoldsChangedHubKey: a pinned hub key that the server no
// longer presents leaves the device without a hub peer until trusted.
func TestDaemonHoldsChangedHubKey(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	cp.enrol(dir, "a")
	pins, err := LoadPins(dir)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := wg.GenerateKey()
	pins.hub = old.PublicKey().String()
	if err := pins.save(); err != nil {
		t.Fatal(err)
	}
	d, fake, stop := startDaemon(t, dir)
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return nm.Generation > 0 })
	last, _ := fake.Last()
	if len(last.Peers) != 0 {
		t.Errorf("held hub configured: %+v", last.Peers)
	}
	lc := NewLocalClient(d.opts.Socket)
	st, err := lc.Status(context.Background())
	if err != nil || len(st.Held) != 1 || st.Held[0].Name != HubName || st.Hub == nil || st.Hub.Path != PathKeyChanged || st.Hub.IPv4 != "100.64.0.1" {
		t.Fatalf("status with held hub: held=%+v hub=%+v err=%v", st.Held, st.Hub, err)
	}
	if _, err := lc.Trust(context.Background(), HubName); err != nil {
		t.Fatal(err)
	}
	last, _ = fake.Last()
	if len(last.Peers) != 1 || last.Peers[0].PublicKey != cp.hubKey.PublicKey() {
		t.Errorf("device after trusting the hub: %+v", last.Peers)
	}
	if st, _ = lc.Status(context.Background()); len(st.Held) != 0 || st.Hub == nil || st.Hub.Path == PathKeyChanged {
		t.Errorf("status after trust: %+v %+v", st.Held, st.Hub)
	}
}

func TestNewDaemonRejectsCorruptPins(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	cp.enrol(dir, "a")
	if err := os.WriteFile(filepath.Join(dir, PinsFile), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDaemon(DaemonOptions{StateDir: dir, Socket: shortSocket(t)}); err == nil || !strings.Contains(err.Error(), PinsFile) {
		t.Errorf("corrupt pins accepted: %v", err)
	}
}
