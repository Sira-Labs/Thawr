package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/stun"
	"github.com/sira-labs/thawr/internal/wg"
)

// TestServerAnswersSTUN: the bound STUN listeners answer binding
// requests with the caller's address, and clients get them in the netmap.
func TestServerAnswersSTUN(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.Listen.STUN = []string{"127.0.0.1:0", "127.0.0.1:0"}
	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)

	addrs := h.srv.STUNAddrs()
	if len(addrs) != 2 {
		t.Fatalf("STUN listeners: %v", addrs)
	}
	var servers []netip.AddrPort
	for _, a := range addrs {
		servers = append(servers, netip.MustParseAddrPort(a))
	}
	ctx := context.Background()
	tr, err := stun.NewSocketTransport(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	res, err := stun.Discover(ctx, tr, servers, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(stun.LocalPort(tr)))
	if len(res.Mapped) != 2 || res.Mapped[0] != want || res.Mapped[1] != want || res.Symmetric {
		t.Fatalf("Discover: %+v want %s twice", res, want)
	}
	// The advertised addresses use the public host and the listen ports.
	secret := createTokenLocal(t, cfg.AdminSocket)
	st, err := client.Enroll(ctx, client.Options{Server: "https://" + h.srv.HTTPSAddr(), Token: secret, Fingerprint: h.srv.tlsFingerprint, StateDir: t.TempDir(), Hostname: "a", Version: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	nm, err := h.srv.netmaps.Build(ctx, st.PeerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.STUN) != 2 || nm.STUN[0] != "127.0.0.1:0" {
		t.Errorf("netmap STUN addrs: %v (advertised from config, ports as configured)", nm.STUN)
	}
}

// TestHubObservedEndpointReachesNetmap: the address a peer's packets
// reach the hub from becomes a reflexive candidate for its peers.
func TestHubObservedEndpointReachesNetmap(t *testing.T) {
	cfg, _ := testConfig(t)
	allowSelfPolicy(t, cfg)
	h := newHarness(t, cfg)
	h.srv.deps.ObserveInterval = 20 * time.Millisecond
	h.srv.deps.HubOptions = control.HubOptions{Coalesce: 10 * time.Millisecond}
	h.start(t)
	defer h.stop(t)

	ctx := context.Background()
	server := "https://" + h.srv.HTTPSAddr()
	dirA, dirB := t.TempDir(), t.TempDir()
	var ids []string
	for _, d := range []struct{ dir, host string }{{dirA, "a"}, {dirB, "b"}} {
		st, err := client.Enroll(ctx, client.Options{Server: server, Token: createTokenLocal(t, cfg.AdminSocket), Fingerprint: h.srv.tlsFingerprint, StateDir: d.dir, Hostname: d.host, Version: "0.1.0"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, st.PeerID)
	}
	keyB, err := client.LoadKey(dirB)
	if err != nil {
		t.Fatal(err)
	}
	seen := netip.MustParseAddrPort("203.0.113.9:4000")
	gen := h.srv.Hub().Generation()
	h.fake.SetStats(wg.PeerStats{PublicKey: keyB.PublicKey(), Endpoint: seen, LastHandshake: time.Now()})
	waitUntil(t, "observed endpoint in a's netmap", func() bool {
		nm, err := h.srv.netmaps.Build(ctx, ids[0])
		if err != nil || len(nm.Peers) != 1 {
			return false
		}
		for _, e := range nm.Peers[0].Endpoints {
			if e.Addr == seen && e.Kind == control.EndpointReflexive {
				return true
			}
		}
		return false
	})
	waitUntil(t, "hub sequence bumped", func() bool { return h.srv.Hub().Generation() > gen })
	// A peer without a handshake (stale or configured endpoint) is ignored.
	keyA, _ := client.LoadKey(dirA)
	h.fake.SetStats(wg.PeerStats{PublicKey: keyA.PublicKey(), Endpoint: netip.MustParseAddrPort("203.0.113.1:1")})
	time.Sleep(60 * time.Millisecond)
	nm, _ := h.srv.netmaps.Build(ctx, ids[1])
	if len(nm.Peers) != 1 || len(nm.Peers[0].Endpoints) != 0 {
		t.Errorf("endpoint without handshake observed: %+v", nm.Peers)
	}
}
