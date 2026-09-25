package server

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

// TestHubPeerAddRemove: a static peer joins the hub interface within a
// second of its creation and leaves it on delete.
func TestHubPeerAddRemove(t *testing.T) {
	cfg, _ := testConfig(t)
	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)
	waitUntil(t, "initial hub config", func() bool { _, ok := h.fake.Last(); return ok })
	mustAdmin(t, h)

	res, err := h.srv.registry.CreateStatic(context.Background(), control.LocalAdmin, control.StaticRequest{OwnerName: "markus", Name: "markus-phone"})
	if err != nil {
		t.Fatal(err)
	}
	pub := res.PrivateKey.PublicKey()
	deadline := time.Now().Add(time.Second)
	for {
		last, _ := h.fake.Last()
		if len(last.Peers) == 1 && last.Peers[0].PublicKey == pub && last.Peers[0].AllowedIPs[0].String() == res.Peer.IPv4+"/32" && !last.Peers[0].Endpoint.IsValid() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("hub did not gain the phone within 1 s: %+v", last.Peers)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if f, ok := h.fake.LastFilter(); !ok || f.Hook != wg.HookForward {
		t.Errorf("hub filter after add: %+v ok=%v", f, ok)
	}
	if code, _ := postLocal(t, cfg.AdminSocket, http.MethodDelete, "/api/v1/peers/markus-phone", nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	waitUntil(t, "hub drops the phone", func() bool { last, _ := h.fake.Last(); return len(last.Peers) == 0 })
}

// TestStaticPresence: a fresh hub handshake makes a static peer online
// and touches its last-seen time; a stale one makes it offline again.
func TestStaticPresence(t *testing.T) {
	cfg, _ := testConfig(t)
	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)
	mustAdmin(t, h)
	ctx := context.Background()
	res, err := h.srv.registry.CreateStatic(ctx, control.LocalAdmin, control.StaticRequest{OwnerName: "markus", Name: "markus-phone"})
	if err != nil {
		t.Fatal(err)
	}
	if h.srv.Online(res.Peer.ID) {
		t.Fatal("phone online before any handshake")
	}
	// The fake reports stats only for configured peers: wait for the hub.
	waitUntil(t, "hub has the phone", func() bool { last, _ := h.fake.Last(); return len(last.Peers) == 1 })
	now := time.Now()
	h.fake.SetStats(wg.PeerStats{PublicKey: res.PrivateKey.PublicKey(), Endpoint: netip.MustParseAddrPort("203.0.113.7:51820"), LastHandshake: now.Add(-10 * time.Second)})
	if err := h.srv.observeOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if !h.srv.Online(res.Peer.ID) {
		t.Error("phone offline after a fresh handshake")
	}
	stored, err := h.srv.st.Peers().GetByID(ctx, res.Peer.ID)
	if err != nil || stored.LastSeenAt == nil || now.Sub(*stored.LastSeenAt) > time.Minute {
		t.Errorf("last seen not recorded: %+v %v", stored.LastSeenAt, err)
	}
	// The phone's address is not a candidate: phones are reached via the hub only.
	if eps, _ := h.srv.endpoints.Get(res.Peer.ID); len(eps) != 0 {
		t.Errorf("static peer got endpoint candidates: %v", eps)
	}
	h.fake.SetStats(wg.PeerStats{PublicKey: res.PrivateKey.PublicKey(), Endpoint: netip.MustParseAddrPort("203.0.113.7:51820"), LastHandshake: now.Add(-10 * time.Minute)})
	if err := h.srv.observeOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if h.srv.Online(res.Peer.ID) {
		t.Error("phone still online with a stale handshake")
	}
}

// mustAdmin creates the admin user "markus" on a running harness.
func mustAdmin(t *testing.T, h *harness) {
	t.Helper()
	if _, err := h.srv.users.Create(context.Background(), control.LocalAdmin, "markus", store.RoleAdmin, "adminpassword"); err != nil {
		t.Fatal(err)
	}
}

// TestHubFilterForwardsPhoneToAgent: the hub's forward filter must let a
// phone reach its owner's laptop (src static, dst agent), not only the
// laptop reach the phone. Found on the first real run: TCP from the
// phone was dropped while pings passed through the ICMP allowance.
func TestHubFilterForwardsPhoneToAgent(t *testing.T) {
	cfg, _ := testConfig(t)
	allowSelfPolicy(t, cfg)
	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)
	ctx := context.Background()
	// createTokenLocal creates alice; her laptop and her phone must see
	// each other under the self policy.
	tok := createTokenLocal(t, cfg.AdminSocket)
	laptop, err := client.Enroll(ctx, client.Options{Server: "https://" + h.srv.HTTPSAddr(), Token: tok, Fingerprint: h.srv.tlsFingerprint,
		StateDir: t.TempDir(), Hostname: "alice-laptop", Version: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.srv.registry.CreateStatic(ctx, control.LocalAdmin, control.StaticRequest{OwnerName: "alice", Name: "alice-phone"})
	if err != nil {
		t.Fatal(err)
	}
	phone, laptopIP := netip.MustParseAddr(res.Peer.IPv4), netip.MustParseAddr(laptop.IPv4)
	has := func(f wg.FilterSet, src, dst netip.Addr) bool {
		for _, r := range f.Rules {
			if r.Src.Addr() == src && r.Dst == dst && r.Proto == wg.ProtoAny && r.Lo <= 1 && r.Hi == 65535 {
				return true
			}
		}
		return false
	}
	waitUntil(t, "hub filter with both directions", func() bool {
		f, ok := h.fake.LastFilter()
		return ok && f.Hook == wg.HookForward && has(f, phone, laptopIP) && has(f, laptopIP, phone)
	})
	f, _ := h.fake.LastFilter()
	for _, r := range f.Rules {
		if r.Src.Addr() == laptopIP && r.Dst == laptopIP {
			t.Errorf("rule with an agent on both ends does not belong on the hub: %+v", r)
		}
	}
}
