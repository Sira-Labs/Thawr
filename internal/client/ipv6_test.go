package client

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	thawrv1 "github.com/sira-labs/thawr/internal/api/proto/thawr/v1"
	"github.com/sira-labs/thawr/internal/wg"
)

const (
	testOverlay6 = "fd00:1:2:3::/64"
	self6        = "fd00:1:2:3::6440:2"
	exit6        = "fd00:1:2:3::6440:3"
	plain6       = "fd00:1:2:3::6440:4"
)

func mustKey(t *testing.T) wg.Key {
	t.Helper()
	k, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// dualStackNetMap is a netmap for a capable device: an exit node with
// the IPv6 overlay, a peer without it and the hub.
func dualStackNetMap(t *testing.T) NetMap {
	t.Helper()
	return NetMap{
		SelfIPv4: "100.64.0.2", Overlay: "100.64.0.0/10", SelfIPv6: self6, Overlay6: testOverlay6,
		Hub: HubPeer{PublicKey: mustKey(t).PublicKey().String(), AllowedIPs: []string{"100.64.0.1/32", "fd00:1:2:3::6440:1/128"}},
		Peers: []Peer{
			{ID: "gw", Name: "gw", PublicKey: mustKey(t).PublicKey().String(), IPv4: "100.64.0.3", IPv6: exit6, ExitNode: true,
				AllowedIPs: []string{"100.64.0.3/32", exit6 + "/128"}},
			{ID: "old", Name: "old", PublicKey: mustKey(t).PublicKey().String(), IPv4: "100.64.0.4", ExitNode: true,
				AllowedIPs: []string{"100.64.0.4/32"}},
		},
		Filter: []FilterRule{
			{Src: "100.64.0.3", Proto: "tcp", PortLo: 22, PortHi: 22},
			{Src: exit6, Proto: "tcp", PortLo: 22, PortHi: 22},
		},
		Forward: []ForwardRule{
			{Src: "100.64.0.3", Dst: "0.0.0.0/0", Proto: "any", PortLo: 1, PortHi: 65535},
			{Src: exit6, Dst: "::/0", Proto: "any", PortLo: 1, PortHi: 65535},
		},
	}
}

func TestBuildConfigIPv6(t *testing.T) {
	nm := dualStackNetMap(t)
	overlay := netip.MustParsePrefix("100.64.0.0/10")
	cfg, err := BuildConfigWith(nm, mustKey(t), 51820, overlay, "gw")
	if err != nil {
		t.Fatal(err)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("100.64.0.2/10"), netip.MustParsePrefix(self6 + "/64")}; !slices.Equal(cfg.Addresses, want) {
		t.Errorf("addresses %v, want %v", cfg.Addresses, want)
	}
	gw := cfg.Peers[1]
	if want := []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32"), netip.MustParsePrefix(exit6 + "/128"), wg.ExitRoute, wg.ExitRoute6}; !slices.Equal(gw.AllowedIPs, want) {
		t.Errorf("exit node allowed %v, want %v", gw.AllowedIPs, want)
	}
	routes := RoutesOf(cfg, Overlays(nm, overlay)...)
	if want := []netip.Prefix{wg.ExitRoute, wg.ExitRoute6}; !slices.Equal(routes, want) {
		t.Errorf("routes %v, want only the exit routes (the /32s and /128s are on-link)", routes)
	}

	// An exit node without the IPv6 overlay carries IPv4 only.
	cfg, err = BuildConfigWith(nm, mustKey(t), 51820, overlay, "old")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Peers[2].AllowedIPs; slices.Contains(got, wg.ExitRoute6) || !slices.Contains(got, wg.ExitRoute) {
		t.Errorf("IPv4-only exit node allowed %v", got)
	}

	// A device without IPv6 in its netmap gets IPv4 only and no ::/0.
	nm.SelfIPv6, nm.Overlay6 = "", ""
	cfg, err = BuildConfigWith(nm, mustKey(t), 51820, overlay, "gw")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Addresses) != 1 || slices.Contains(cfg.Peers[1].AllowedIPs, wg.ExitRoute6) {
		t.Errorf("incapable device: addresses %v, exit allowed %v", cfg.Addresses, cfg.Peers[1].AllowedIPs)
	}
	if got := Overlays(nm, overlay); len(got) != 1 {
		t.Errorf("overlays without IPv6: %v", got)
	}
}

func TestFilterSetForIPv6(t *testing.T) {
	nm := dualStackNetMap(t)
	overlay := netip.MustParsePrefix("100.64.0.0/10")
	self := netip.MustParseAddr("100.64.0.2")
	set := FilterSetFor(nm, "thawr0", self, overlay, []netip.Prefix{wg.ExitRoute})
	if set.Local6 != netip.MustParseAddr(self6) {
		t.Errorf("Local6 %s", set.Local6)
	}
	for _, a := range []string{exit6, "fd00:1:2:3::6440:1", "100.64.0.1", "100.64.0.3"} {
		if !slices.Contains(set.Visible, netip.MustParseAddr(a)) {
			t.Errorf("%s not visible: %v", a, set.Visible)
		}
	}
	if len(set.Rules) != 2 || set.Rules[1].Src != netip.MustParsePrefix(exit6+"/128") {
		t.Errorf("rules %+v: want the IPv6 source as a /128", set.Rules)
	}
	if len(set.Forward) != 2 || set.Forward[1].Dst != wg.ExitRoute6 || set.Forward[1].Src.Bits() != 128 {
		t.Errorf("forward %+v: want ::/0 from the IPv6 source", set.Forward)
	}
	if !slices.Equal(set.Masquerade, []netip.Prefix{wg.ExitRoute, wg.ExitRoute6}) || set.MasqueradeFrom6 != netip.MustParsePrefix(testOverlay6) {
		t.Errorf("masquerade %v from %s / %s", set.Masquerade, set.MasqueradeFrom, set.MasqueradeFrom6)
	}

	// A subnet router (no exit) does not forward ::/0.
	set = FilterSetFor(nm, "thawr0", self, overlay, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/24")})
	if len(set.Forward) != 0 || slices.Contains(set.Masquerade, wg.ExitRoute6) {
		t.Errorf("subnet router: forward %+v masquerade %v", set.Forward, set.Masquerade)
	}

	// Without the IPv6 overlay an exit node neither forwards nor
	// masquerades IPv6.
	nm.SelfIPv6, nm.Overlay6 = "", ""
	set = FilterSetFor(nm, "thawr0", self, overlay, []netip.Prefix{wg.ExitRoute})
	if set.Local6.IsValid() || len(set.Forward) != 1 || slices.Contains(set.Masquerade, wg.ExitRoute6) || set.MasqueradeFrom6.IsValid() {
		t.Errorf("IPv4-only exit node: %+v", set)
	}
}

func TestNetMapFromProtoIPv6(t *testing.T) {
	m := &thawrv1.NetMap{
		Self:    &thawrv1.SelfInfo{Ipv4: "100.64.0.2", Ipv6: self6, OverlayIpv6: testOverlay6},
		Peers:   []*thawrv1.NetPeer{{Name: "gw", Ipv4: "100.64.0.3", Ipv6: exit6}},
		Filter:  []*thawrv1.FilterRule{{SrcIpv4: "100.64.0.3", Proto: "tcp", PortLo: 22, PortHi: 22}, {SrcIpv6: exit6, Proto: "tcp", PortLo: 22, PortHi: 22}},
		Forward: []*thawrv1.ForwardRule{{SrcIpv6: exit6, DstCidr: "::/0", Proto: "any", PortLo: 1, PortHi: 65535}},
	}
	nm := NetMapFromProto(m, time.Now())
	if nm.SelfIPv6 != self6 || nm.Overlay6 != testOverlay6 || nm.Peers[0].IPv6 != exit6 {
		t.Errorf("netmap %+v", nm)
	}
	if nm.Filter[0].Src != "100.64.0.3" || nm.Filter[1].Src != exit6 || nm.Forward[0].Src != exit6 {
		t.Errorf("rule sources: filter %+v forward %+v", nm.Filter, nm.Forward)
	}
}

func TestAdoptSelfIPv6(t *testing.T) {
	st := State{IPv4: "100.64.0.2"}
	if !adoptSelfIPv6(&st, NetMap{SelfIPv6: self6, Overlay6: testOverlay6}) || st.IPv6 != self6 || st.OverlayIPv6 != testOverlay6 {
		t.Errorf("first netmap with IPv6: %+v", st)
	}
	if adoptSelfIPv6(&st, NetMap{SelfIPv6: self6, Overlay6: testOverlay6}) {
		t.Error("unchanged netmap reported a change")
	}
	if !adoptSelfIPv6(&st, NetMap{}) || st.IPv6 != "" {
		t.Errorf("netmap without IPv6 kept %+v", st)
	}
	// A malformed address in the netmap gives no IPv6 address.
	if _, _, ok := (NetMap{SelfIPv6: "100.64.0.2", Overlay6: testOverlay6}).selfIPv6(); ok {
		t.Error("an IPv4 address accepted as the IPv6 one")
	}
	if _, _, ok := (NetMap{SelfIPv6: "fd00:9::1", Overlay6: testOverlay6}).selfIPv6(); ok {
		t.Error("an address outside the prefix accepted")
	}
}
