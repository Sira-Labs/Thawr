package server

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/dns"
)

// TestHubResolverHonoursVisibility: the hub resolver answers a phone
// only with the peers the policy lets it see, plus the hub itself, and
// serves over the bound listener.
func TestHubResolverHonoursVisibility(t *testing.T) {
	cfg, _ := testConfig(t)
	allowSelfPolicy(t, cfg)
	cfg.DNS.Enabled = true
	cfg.DNS.Upstream = []string{"127.0.0.1:1"} // never asked in this test
	var mu sync.Mutex
	var listenAddr string
	h := newHarness(t, cfg, func(d *Deps) {
		d.DNSListen = func(ctx context.Context, addr netip.AddrPort) (net.PacketConn, net.Listener, error) {
			if addr.String() != "100.64.0.1:53" {
				t.Errorf("hub resolver bound to %s", addr)
			}
			udp, tcp, err := dns.Listen(ctx, netip.MustParseAddrPort("127.0.0.1:0"))
			if err == nil {
				mu.Lock()
				listenAddr = udp.LocalAddr().String()
				mu.Unlock()
			}
			return udp, tcp, err
		}
	})
	h.start(t)
	defer h.stop(t)
	ctx := context.Background()

	tok := createTokenLocal(t, cfg.AdminSocket)
	laptop, err := client.Enroll(ctx, client.Options{Server: "https://" + h.srv.HTTPSAddr(), Token: tok, Fingerprint: h.srv.tlsFingerprint,
		StateDir: t.TempDir(), Hostname: "alice-laptop", Version: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	phone, err := h.srv.registry.CreateStatic(ctx, control.LocalAdmin, control.StaticRequest{OwnerName: "alice", Name: "alice-phone"})
	if err != nil {
		t.Fatal(err)
	}
	if code, body := postLocal(t, cfg.AdminSocket, http.MethodPost, "/api/v1/users", map[string]string{"name": "bob", "role": "member", "password": "bobpassword1"}); code != http.StatusCreated {
		t.Fatalf("create bob: %d %s", code, body)
	}
	bobPhone, err := h.srv.registry.CreateStatic(ctx, control.LocalAdmin, control.StaticRequest{OwnerName: "bob", Name: "bob-phone"})
	if err != nil {
		t.Fatal(err)
	}
	phoneIP, laptopIP, bobIP := netip.MustParseAddr(phone.Peer.IPv4), netip.MustParseAddr(laptop.IPv4), netip.MustParseAddr(bobPhone.Peer.IPv4)
	src := h.srv.dnsSource

	if a, ok := src.Lookup(ctx, phoneIP, "alice-laptop"); !ok || a != laptopIP {
		t.Errorf("phone -> alice-laptop: %v %v", a, ok)
	}
	if a, ok := src.Lookup(ctx, phoneIP, "Alice-Laptop"); !ok || a != laptopIP {
		t.Errorf("case-insensitive lookup: %v %v", a, ok)
	}
	if _, ok := src.Lookup(ctx, phoneIP, "bob-phone"); ok {
		t.Error("phone learned bob-phone, which the policy hides")
	}
	if a, ok := src.Lookup(ctx, bobIP, "bob-phone"); !ok || a != bobIP {
		t.Errorf("a peer resolves itself: %v %v", a, ok)
	}
	if _, ok := src.Lookup(ctx, netip.MustParseAddr("100.64.9.9"), "alice-laptop"); ok {
		t.Error("unknown requester learned a peer")
	}
	if a, ok := src.Lookup(ctx, netip.MustParseAddr("100.64.9.9"), "hub"); !ok || a.String() != "100.64.0.1" {
		t.Errorf("hub for anyone: %v %v", a, ok)
	}
	if n, ok := src.Reverse(ctx, phoneIP, laptopIP); !ok || n != "alice-laptop" {
		t.Errorf("reverse laptop: %q %v", n, ok)
	}
	if _, ok := src.Reverse(ctx, phoneIP, bobIP); ok {
		t.Error("reverse of a hidden peer answered")
	}
	if n, ok := src.Reverse(ctx, phoneIP, netip.MustParseAddr("100.64.0.1")); !ok || n != "hub" {
		t.Errorf("reverse hub: %q %v", n, ok)
	}
	// The server host itself (loopback) sees every name.
	if a, ok := src.Lookup(ctx, netip.MustParseAddr("127.0.0.1"), "bob-phone"); !ok || a != bobIP {
		t.Errorf("local host lookup: %v %v", a, ok)
	}

	// A removed peer disappears with the next generation.
	if err := h.srv.registry.Delete(ctx, control.LocalAdmin, "bob-phone"); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "bob-phone gone from the resolver", func() bool {
		_, ok := src.Lookup(ctx, netip.MustParseAddr("127.0.0.1"), "bob-phone")
		return !ok
	})

	// The listener answers real queries (from loopback here).
	mu.Lock()
	addr := listenAddr
	mu.Unlock()
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", addr)
	}}
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := r.LookupNetIP(qctx, "ip4", "alice-laptop.thawr")
	if err != nil || len(ips) != 1 || ips[0] != laptopIP {
		t.Fatalf("query over the listener: %v %v", ips, err)
	}
	st, err := h.srv.Status(ctx)
	if err != nil || st.DNSListen != "100.64.0.1:53" {
		t.Errorf("status dns_listen: %q %v", st.DNSListen, err)
	}
}

// TestHubResolverDisabled: dns.enabled false binds nothing and the
// phone config carries no DNS line.
func TestHubResolverDisabled(t *testing.T) {
	cfg, _ := testConfig(t)
	h := newHarness(t, cfg, func(d *Deps) {
		d.DNSListen = func(context.Context, netip.AddrPort) (net.PacketConn, net.Listener, error) {
			t.Error("resolver bound while disabled")
			return nil, nil, nil
		}
	})
	h.start(t)
	defer h.stop(t)
	st, err := h.srv.Status(context.Background())
	if err != nil || st.DNSListen != "" {
		t.Errorf("status dns_listen: %q %v", st.DNSListen, err)
	}
}
