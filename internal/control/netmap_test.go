package control

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/store"
)

type fakePresence map[string]bool

func (f fakePresence) Online(id string) bool { return f[id] }

func TestNetMapBuilder(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	alice := mustUser(t, env.users, "alice", store.RoleMember)
	bob := mustUser(t, env.users, "bob", store.RoleMember)
	a1, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a1")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a2")
	if err != nil {
		t.Fatal(err)
	}
	b1, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "bob"}), "b1")
	if err != nil {
		t.Fatal(err)
	}
	// A static (mobile) peer of alice, reached through the hub.
	phone := store.Peer{ID: "phone", Name: "alice-phone", Kind: store.KindHuman, Mode: store.ModeStatic, OwnerID: alice.ID,
		PublicKey: newPubKey(t), IPv4: "100.64.0.21", CreatedAt: env.clk.Now()}
	if err := env.st.Peers().Create(ctx, phone); err != nil {
		t.Fatal(err)
	}
	_ = bob

	eps := NewEndpointTable(env.clk.Now)
	if _, err := eps.Set(a2.Peer.ID, []Endpoint{{Addr: netip.MustParseAddrPort("192.168.1.5:41820"), Kind: EndpointLocal}}, true, 41820); err != nil {
		t.Fatal(err)
	}
	hub := HubConfig{PublicKey: "HUBKEY", Endpoint: "vpn.example.com:51820", Address: netip.MustParseAddr("100.64.0.1"), Overlay: netip.MustParsePrefix("100.64.0.0/10"),
		STUNAddrs: []string{"vpn.example.com:3478", "vpn.example.com:3479"}}
	b := NewNetMapBuilder(env.st, OwnerVisibility{}, eps, fakePresence{a2.Peer.ID: true}, hub, func() int64 { return 42 })

	nm, err := b.Build(ctx, a1.Peer.ID)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(nm.STUN) != 2 || nm.STUN[1] != "vpn.example.com:3479" {
		t.Errorf("STUN addrs: %v", nm.STUN)
	}
	if nm.Generation != 42 || nm.SelfID != a1.Peer.ID || nm.SelfName != "a1" || nm.SelfKind != a1.Peer.Kind || nm.SelfIPv4.String() != a1.Peer.IPv4 || nm.Overlay != hub.Overlay {
		t.Errorf("self: %+v", nm)
	}
	if len(nm.Peers) != 2 || nm.Peers[0].ID != a2.Peer.ID || nm.Peers[1].ID != "phone" {
		t.Fatalf("visible peers: %+v (want a2 and the phone)", nm.Peers)
	}
	if ph := nm.Peers[1]; !ph.ViaHub || ph.IPv4.String() != "100.64.0.21" || ph.Owner != "alice" || len(ph.Endpoints) != 0 || ph.PublicKey != phone.PublicKey {
		t.Errorf("phone entry: %+v", ph)
	}
	p := nm.Peers[0]
	if !p.Online || !p.Symmetric || len(p.Endpoints) != 1 || p.Endpoints[0].Addr.String() != "192.168.1.5:41820" || p.PublicKey != a2.Peer.PublicKey || p.Owner != "alice" {
		t.Errorf("peer a2: %+v", p)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != a2.Peer.IPv4+"/32" {
		t.Errorf("allowed ips: %v", p.AllowedIPs)
	}
	wantHub := []string{"100.64.0.1/32", "100.64.0.21/32"}
	if nm.Hub.PublicKey != "HUBKEY" || nm.Hub.Endpoint != "vpn.example.com:51820" || len(nm.Hub.AllowedIPs) != 2 ||
		nm.Hub.AllowedIPs[0].String() != wantHub[0] || nm.Hub.AllowedIPs[1].String() != wantHub[1] {
		t.Errorf("hub: %+v", nm.Hub)
	}

	// bob sees nobody but the hub, and not alice's phone.
	nmB, err := b.Build(ctx, b1.Peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nmB.Peers) != 0 || len(nmB.Hub.AllowedIPs) != 1 {
		t.Errorf("bob's map: peers=%d hub=%v", len(nmB.Peers), nmB.Hub.AllowedIPs)
	}
	if _, err := b.Build(ctx, "missing"); err == nil {
		t.Error("missing peer should fail")
	}
}

func TestNetMapNoSecrets(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	mustUser(t, env.users, "alice", store.RoleMember)
	a1, _ := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a1")
	a2, _ := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a2")
	b := NewNetMapBuilder(env.st, OwnerVisibility{}, nil, nil, HubConfig{Overlay: netip.MustParsePrefix("100.64.0.0/10")}, func() int64 { return 1 })
	nm, err := b.Build(ctx, a1.Peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	dump := strings.ToLower(fmtNetMap(nm))
	for _, secret := range []string{a2.NodeSecret, a2.Peer.NodeSecretHash, a1.NodeSecret} {
		if strings.Contains(dump, strings.ToLower(secret)) {
			t.Errorf("netmap contains secret material")
		}
	}
}

func fmtNetMap(nm NetMap) string {
	var sb strings.Builder
	sb.WriteString(nm.SelfID + nm.SelfName)
	for _, p := range nm.Peers {
		sb.WriteString(p.ID + p.Name + p.Kind + p.PublicKey + p.IPv4.String())
	}
	sb.WriteString(nm.Hub.PublicKey + nm.Hub.Endpoint)
	return sb.String()
}

func TestEndpointTable(t *testing.T) {
	clk := newClock()
	tab := NewEndpointTable(clk.Now)
	good := []Endpoint{{Addr: netip.MustParseAddrPort("203.0.113.5:41820"), Kind: EndpointReflexive}}
	changed, err := tab.Set("p", good, false, 41820)
	if err != nil || !changed {
		t.Fatalf("first set: changed=%v err=%v", changed, err)
	}
	if changed, _ := tab.Set("p", good, false, 41820); changed {
		t.Error("identical report counted as change")
	}
	if changed, _ := tab.Set("p", good, true, 41820); !changed {
		t.Error("symmetric flip not a change")
	}
	if eps, sym := tab.Get("p"); len(eps) != 1 || !sym {
		t.Errorf("Get: %v %v", eps, sym)
	}
	// The hub-observed address joins the list as a reflexive candidate,
	// deduplicated against reported ones and expiring like them.
	observed := netip.MustParseAddrPort("203.0.113.5:41821")
	if !tab.SetObserved("p", observed) {
		t.Error("first observation not a change")
	}
	if tab.SetObserved("p", observed) {
		t.Error("same observation counted as change")
	}
	if tab.SetObserved("p", netip.MustParseAddrPort("127.0.0.1:5")) || tab.SetObserved("p", netip.MustParseAddrPort("0.0.0.0:5")) {
		t.Error("unroutable observation accepted")
	}
	if eps, _ := tab.Get("p"); len(eps) != 2 || eps[1].Addr != observed || eps[1].Kind != EndpointReflexive {
		t.Errorf("Get with observed: %v", eps)
	}
	tab.SetObserved("p", good[0].Addr)
	if eps, _ := tab.Get("p"); len(eps) != 1 {
		t.Errorf("observed duplicate not merged: %v", eps)
	}
	tab.SetObserved("r", observed)
	if eps, sym := tab.Get("r"); len(eps) != 1 || sym {
		t.Errorf("observed-only peer: %v %v", eps, sym)
	}
	clk.Advance(endpointTTL + time.Second)
	if eps, _ := tab.Get("p"); eps != nil {
		t.Error("expired entry still returned")
	}
	if eps, _ := tab.Get("r"); eps != nil {
		t.Error("expired observation still returned")
	}
	tab.SetObserved("p", observed)
	tab.Delete("p")
	if eps, _ := tab.Get("p"); eps != nil {
		t.Error("Delete kept the observation")
	}
	bad := [][]Endpoint{
		{{Addr: netip.MustParseAddrPort("127.0.0.1:1"), Kind: EndpointLocal}},
		{{Addr: netip.MustParseAddrPort("0.0.0.0:1"), Kind: EndpointLocal}},
		{{Addr: netip.MustParseAddrPort("10.0.0.1:0"), Kind: EndpointLocal}},
		{{Addr: netip.MustParseAddrPort("10.0.0.1:5"), Kind: 0}},
		make([]Endpoint, MaxEndpoints+1),
	}
	for _, b := range bad {
		if _, err := tab.Set("q", b, false, 1); err == nil {
			t.Errorf("accepted invalid report %v", b)
		}
	}
	if _, err := ParseEndpoint("nope", EndpointLocal); err == nil {
		t.Error("ParseEndpoint accepted garbage")
	}
	paths := NewPathTable(clk.Now)
	paths.Set("p", []PathState{{PeerID: "q", State: "direct", Endpoint: "1.2.3.4:5"}})
	if got := paths.Get("p"); len(got) != 1 || got[0].State != "direct" || got[0].Updated.IsZero() {
		t.Errorf("paths: %+v", got)
	}
}
