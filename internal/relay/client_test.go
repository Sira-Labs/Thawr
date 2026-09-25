package relay_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sira-labs/thawr/internal/api"
	"github.com/sira-labs/thawr/internal/relay"
	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

type nodeAuth map[string]store.Peer

func (n nodeAuth) PeerByNodeSecret(_ context.Context, secret string) (store.Peer, error) {
	p, ok := n[secret]
	if !ok {
		return store.Peer{}, errors.New("unknown secret")
	}
	return p, nil
}

type allVisible struct{}

func (allVisible) Visible(context.Context, relay.Key, relay.Key) (bool, error) { return true, nil }

// relayHost runs the relay behind the real upgrade handler.
type relayHost struct {
	ts     *httptest.Server
	srv    *relay.Server
	tlsCfg *tls.Config
	keys   map[string]relay.Key
}

func startHost(t *testing.T, secrets ...string) *relayHost {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	auth, keys := nodeAuth{}, map[string]relay.Key{}
	for _, s := range secrets {
		k, err := wg.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[s] = relay.Key(k.PublicKey())
		auth[s] = store.Peer{ID: s, Name: s, PublicKey: k.PublicKey().String()}
	}
	srv := relay.NewServer(allVisible{}, relay.ServerOptions{PingInterval: 200 * time.Millisecond, Logger: quiet})
	h, err := api.NewREST(api.RESTDeps{Status: statusStub{}, UI: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("x")}}, Logger: quiet, NodeAuth: auth, Relay: srv})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(h)
	t.Cleanup(func() { srv.Close(); ts.Close() })
	return &relayHost{ts: ts, srv: srv, tlsCfg: ts.Client().Transport.(*http.Transport).TLSClientConfig.Clone(), keys: keys}
}

type statusStub struct{}

func (statusStub) Status(context.Context) (api.Status, error) { return api.Status{}, nil }

// fakeWG is a UDP socket standing in for the local WireGuard port.
type fakeWG struct {
	conn *net.UDPConn
	port int
}

func newFakeWG(t *testing.T) *fakeWG {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	uc := pc.(*net.UDPConn)
	return &fakeWG{conn: uc, port: uc.LocalAddr().(*net.UDPAddr).Port}
}

func (f *fakeWG) send(t *testing.T, to net.Addr, payload []byte) {
	t.Helper()
	if _, err := f.conn.WriteTo(payload, to); err != nil {
		t.Fatal(err)
	}
}

// exchange sends payload to via and waits for it on dst, retrying a few
// times: the relay has UDP semantics and a frame sent during a
// reconnect is lost by design.
func exchange(t *testing.T, src *fakeWG, via net.Addr, dst *fakeWG, payload []byte) (*net.UDPAddr, bool) {
	t.Helper()
	for range 5 {
		src.send(t, via, payload)
		got, from, ok := dst.recv(time.Second)
		if ok && string(got) == string(payload) {
			return from, true
		}
	}
	return nil, false
}

func (f *fakeWG) recv(timeout time.Duration) ([]byte, *net.UDPAddr, bool) {
	buf := make([]byte, 2000)
	_ = f.conn.SetReadDeadline(time.Now().Add(timeout))
	n, from, err := f.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, false
	}
	return buf[:n], from, true
}

func newClient(t *testing.T, host *relayHost, secret string, wgPort int, mod func(*relay.ClientOptions)) *relay.Client {
	t.Helper()
	opts := relay.ClientOptions{ServerURL: host.ts.URL, TLS: host.tlsCfg, NodeSecret: secret, WireGuardPort: wgPort,
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 100 * time.Millisecond, PingInterval: 200 * time.Millisecond,
		ReleaseDelay: 20 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if mod != nil {
		mod(&opts)
	}
	c := relay.NewClient(opts)
	t.Cleanup(c.Close)
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRelayClientProxy(t *testing.T) {
	host := startHost(t, "sa", "sb")
	wgA, wgB := newFakeWG(t), newFakeWG(t)
	a := newClient(t, host, "sa", wgA.port, nil)
	b := newClient(t, host, "sb", wgB.port, nil)
	if a.Connected() {
		t.Fatal("connected before any peer needed the relay")
	}
	ctx := context.Background()
	proxyAB, err := a.Endpoint(ctx, host.keys["sb"]) // a's endpoint for b
	if err != nil {
		t.Fatal(err)
	}
	proxyBA, err := b.Endpoint(ctx, host.keys["sa"])
	if err != nil {
		t.Fatal(err)
	}
	if !proxyAB.Addr().IsLoopback() || !proxyBA.Addr().IsLoopback() {
		t.Fatalf("proxies not on loopback: %s %s", proxyAB, proxyBA)
	}
	waitFor(t, "both connected", func() bool { return a.Connected() && b.Connected() && host.srv.Stats().Sessions == 2 })

	// WireGuard A sends to its proxy; WireGuard B receives from its proxy.
	payload := []byte{1, 0, 0, 0, 9, 9, 9}
	from, ok := exchange(t, wgA, net.UDPAddrFromAddrPort(proxyAB), wgB, payload)
	if !ok || from.AddrPort() != proxyBA {
		t.Fatalf("b: ok=%v from %v (want from %s)", ok, from, proxyBA)
	}
	// And back.
	reply := []byte{4, 0, 0, 0, 1}
	from, ok = exchange(t, wgB, net.UDPAddrFromAddrPort(proxyBA), wgA, reply)
	if !ok || from.AddrPort() != proxyAB {
		t.Fatalf("a: ok=%v from %v (want from %s)", ok, from, proxyAB)
	}
	// Non-WireGuard datagrams never leave the host.
	wgA.send(t, net.UDPAddrFromAddrPort(proxyAB), []byte{0, 0, 0, 0, 1})
	if _, _, ok := wgB.recv(100 * time.Millisecond); ok {
		t.Fatal("non-WireGuard datagram relayed")
	}
	if st := host.srv.Stats(); st.Frames < 2 || a.Peers() != 1 {
		t.Errorf("stats %+v peers %d", st, a.Peers())
	}
	// Endpoint is stable for the same peer.
	if again, _ := a.Endpoint(ctx, host.keys["sb"]); again != proxyAB {
		t.Errorf("proxy address changed: %s vs %s", again, proxyAB)
	}
}

func TestRelayClientIdleClose(t *testing.T) {
	host := startHost(t, "sa")
	wgA := newFakeWG(t)
	a := newClient(t, host, "sa", wgA.port, func(o *relay.ClientOptions) { o.IdleTimeout = 100 * time.Millisecond })
	var other relay.Key
	other[0] = 1
	ep, err := a.Endpoint(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "connected", a.Connected)
	a.Release(other)
	// Asking again inside the release delay keeps the proxy.
	if ep2, _ := a.Endpoint(context.Background(), other); ep2 != ep {
		t.Fatalf("proxy recreated during release delay")
	}
	a.Release(other)
	waitFor(t, "proxy released", func() bool { return a.Peers() == 0 })
	waitFor(t, "connection idled out", func() bool { return !a.Connected() && host.srv.Stats().Sessions == 0 })
	// A new peer reopens it.
	if _, err := a.Endpoint(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "reconnected", a.Connected)
}

func TestRelayClientReconnect(t *testing.T) {
	host := startHost(t, "sa", "sb")
	wgA, wgB := newFakeWG(t), newFakeWG(t)
	a := newClient(t, host, "sa", wgA.port, nil)
	b := newClient(t, host, "sb", wgB.port, nil)
	ctx := context.Background()
	proxyAB, _ := a.Endpoint(ctx, host.keys["sb"])
	proxyBA, _ := b.Endpoint(ctx, host.keys["sa"])
	waitFor(t, "both connected", func() bool { return host.srv.Stats().Sessions == 2 })
	// The server drops every session (a restart, from the client's view).
	host.srv.Prune(func(relay.Key) bool { return false })
	waitFor(t, "sessions gone", func() bool { return host.srv.Stats().Sessions == 0 })
	waitFor(t, "both reconnected", func() bool { return host.srv.Stats().Sessions == 2 && a.Connected() && b.Connected() })
	payload := []byte{2, 0, 0, 0, 5}
	if from, ok := exchange(t, wgA, net.UDPAddrFromAddrPort(proxyAB), wgB, payload); !ok || from.AddrPort() != proxyBA {
		t.Fatalf("after reconnect: ok=%v from %v", ok, from)
	}
}
