package control

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	"github.com/sira-labs/thawr/internal/store"
)

// dualVisibility lets everyone see everyone and opens port 22 from both
// families of a1 on every receiver; a1 may use b as an exit node.
type dualVisibility struct{ OwnerVisibility }

func (dualVisibility) Visible(_, _ store.Peer) bool { return true }

func (dualVisibility) FilterFor(store.Peer) []FilterRule {
	return []FilterRule{
		{Src: netip.MustParseAddr("100.64.0.2"), Proto: "tcp", PortLo: 22, PortHi: 22},
		{Src: netip.MustParseAddr("fd3a:9c1e:44b0::6440:2"), Proto: "tcp", PortLo: 22, PortHi: 22},
	}
}

func (dualVisibility) Routing(store.Peer) Routing {
	return Routing{ExitNodes: []string{"b"}, Forward: []ForwardRule{
		{Src: netip.MustParseAddr("100.64.0.2"), Dst: netip.MustParsePrefix("0.0.0.0/0"), Proto: "any", PortLo: 1, PortHi: 65535},
		{Src: netip.MustParseAddr("fd3a:9c1e:44b0::6440:2"), Dst: netip.MustParsePrefix("::/0"), Proto: "any", PortLo: 1, PortHi: 65535},
	}}
}

func TestNetMapIPv6(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	mk := func(id, v4, v6 string, capable bool, mode string) {
		t.Helper()
		if err := st.Peers().Create(ctx, store.Peer{ID: id, Name: id, Kind: store.KindHuman, Mode: mode,
			PublicKey: newPubKey(t), IPv4: v4, IPv6: v6, IPv6Capable: capable}); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", "100.64.0.2", "fd3a:9c1e:44b0::6440:2", true, store.ModeAgent)
	mk("b", "100.64.0.3", "fd3a:9c1e:44b0::6440:3", true, store.ModeAgent)
	mk("old", "100.64.0.4", "fd3a:9c1e:44b0::6440:4", false, store.ModeAgent)
	mk("phone", "100.64.0.5", "fd3a:9c1e:44b0::6440:5", true, store.ModeStatic)

	hub4 := HubConfig{PublicKey: "HUBKEY", Endpoint: "vpn:51820", Address: netip.MustParseAddr("100.64.0.1"), Overlay: netip.MustParsePrefix("100.64.0.0/10")}
	hub6 := hub4
	hub6.Address6, hub6.Overlay6 = netip.MustParseAddr("fd3a:9c1e:44b0::6440:1"), netip.MustParsePrefix("fd3a:9c1e:44b0::/64")
	gen := func() int64 { return 7 }
	b6 := NewNetMapBuilder(st, dualVisibility{}, nil, nil, hub6, gen)

	nm, err := b6.Build(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if nm.SelfIPv6.String() != "fd3a:9c1e:44b0::6440:2" || nm.Overlay6 != hub6.Overlay6 {
		t.Errorf("self ipv6 = %s overlay6 = %s", nm.SelfIPv6, nm.Overlay6)
	}
	byID := map[string]NetPeer{}
	for _, p := range nm.Peers {
		byID[p.ID] = p
	}
	if p := byID["b"]; p.IPv6.String() != "fd3a:9c1e:44b0::6440:3" || !p.ExitNode ||
		!reflect.DeepEqual(p.AllowedIPs, []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32"), netip.MustParsePrefix("fd3a:9c1e:44b0::6440:3/128")}) {
		t.Errorf("capable peer b: %+v", p)
	}
	// A peer whose client did not ask for IPv6 gets no address that would
	// blackhole traffic.
	if p := byID["old"]; p.IPv6.IsValid() || len(p.AllowedIPs) != 1 {
		t.Errorf("incapable peer old: %+v", p)
	}
	wantHub := []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd3a:9c1e:44b0::6440:1/128"),
		netip.MustParsePrefix("100.64.0.5/32"), netip.MustParsePrefix("fd3a:9c1e:44b0::6440:5/128")}
	if !reflect.DeepEqual(nm.Hub.AllowedIPs, wantHub) || byID["phone"].IPv6.String() != "fd3a:9c1e:44b0::6440:5" {
		t.Errorf("hub allowed ips = %v, phone = %+v", nm.Hub.AllowedIPs, byID["phone"])
	}
	if len(nm.Filter) != 2 || len(nm.Forward) != 2 {
		t.Errorf("capable receiver lost rules: filter %v forward %v", nm.Filter, nm.Forward)
	}

	// The incapable receiver gets exactly the netmap a server without
	// IPv6 builds for it.
	got, err := b6.Build(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	want, err := NewNetMapBuilder(st, dualVisibility{}, nil, nil, hub4, gen).Build(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	want.Filter, want.Forward = ipv4Filter(want.Filter), ipv4Forward(want.Forward)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("incapable receiver's netmap differs from the IPv4-only one:\n got %+v\nwant %+v", got, want)
	}
	if got.SelfIPv6.IsValid() || len(got.Filter) != 1 || got.Filter[0].Src.Is6() || len(got.Forward) != 1 {
		t.Errorf("incapable receiver: self6 %s filter %v forward %v", got.SelfIPv6, got.Filter, got.Forward)
	}
	for _, p := range got.Peers {
		if p.IPv6.IsValid() {
			t.Errorf("incapable receiver sees %s's IPv6", p.ID)
		}
	}
}
