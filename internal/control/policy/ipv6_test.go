package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

var overlay6 = netip.MustParsePrefix("fd3a:9c1e:44b0::/64")

const ipv6Policy = `version: 1
acls:
  - action: accept
    src: [alice]
    dst: ["peer:markus-box:22"]
  - action: accept
    src: [markus]
    dst: ["internet:*", "10.1.0.0/24:80"]
  - action: accept
    src: ["fd3a:9c1e:44b0::6440:4"]
    dst: ["[fd3a:9c1e:44b0::6440:2]:443"]
`

// ipv6Peers has every peer dual-stack except bob-box, which has no IPv6
// address (a peer the server has not assigned one yet).
func ipv6Peers() []Peer {
	pfx := netip.MustParsePrefix
	return []Peer{
		{ID: "p1", Name: "markus-box", Owner: "markus", IPv4: ip("100.64.0.2"), IPv6: ip("fd3a:9c1e:44b0::6440:2")},
		{ID: "p2", Name: "alice-laptop", Owner: "alice", IPv4: ip("100.64.0.3"), IPv6: ip("fd3a:9c1e:44b0::6440:3")},
		{ID: "p3", Name: "bob-box", Owner: "bob", IPv4: ip("100.64.0.4")},
		{ID: "p4", Name: "carol", Owner: "carol", IPv4: ip("100.64.0.5"), IPv6: ip("fd3a:9c1e:44b0::6440:4")},
		{ID: "p5", Name: "nas", Owner: "ops", IPv4: ip("100.64.0.6"), IPv6: ip("fd3a:9c1e:44b0::6440:6"),
			Routes: []netip.Prefix{ExitPrefix, pfx("10.1.0.0/24")}},
	}
}

func compileIPv6(t *testing.T) *Compiled {
	t.Helper()
	p, err := Parse([]byte(ipv6Policy))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Validate(Registry{Users: []string{"alice", "bob", "markus", "carol"}, Peers: []string{"markus-box"}, Overlay: overlay, Overlay6: overlay6}); err != nil {
		t.Fatal(err)
	}
	return CompileWith(p, ipv6Peers(), overlay)
}

func TestFilterForBothFamilies(t *testing.T) {
	c := compileIPv6(t)
	// alice reaches markus-box:22 from both of her addresses; carol's
	// IPv6 selector opens 443 only from that one address; nothing for
	// bob, whose rules do not exist.
	got := fmt.Sprint(c.FilterFor("p1"))
	want := fmt.Sprint([]FilterRule{
		{Src: ip("100.64.0.3"), Proto: ProtoAny, Lo: 22, Hi: 22},
		{Src: ip("100.64.0.5"), Proto: ProtoAny, Lo: 443, Hi: 443},
		{Src: ip("fd3a:9c1e:44b0::6440:3"), Proto: ProtoAny, Lo: 22, Hi: 22},
		{Src: ip("fd3a:9c1e:44b0::6440:4"), Proto: ProtoAny, Lo: 443, Hi: 443},
	})
	if got != want {
		t.Errorf("FilterFor(markus-box):\n got %s\nwant %s", got, want)
	}
	if !c.Visible("p4", "p1") {
		t.Error("an IPv6 selector did not make the peers visible")
	}
}

func TestForwardForInternetBothFamilies(t *testing.T) {
	c := compileIPv6(t)
	// The internet goes out through the exit node in both families; the
	// IPv4 subnet route stays IPv4.
	got := fmt.Sprint(c.ForwardFor("p5"))
	want := fmt.Sprint([]ForwardRule{
		{Src: ip("100.64.0.2"), Dst: ExitPrefix, Proto: ProtoAny, Lo: 1, Hi: 65535},
		{Src: ip("100.64.0.2"), Dst: netip.MustParsePrefix("10.1.0.0/24"), Proto: ProtoAny, Lo: 80, Hi: 80},
		{Src: ip("fd3a:9c1e:44b0::6440:2"), Dst: ExitPrefix6, Proto: ProtoAny, Lo: 1, Hi: 65535},
	})
	if got != want {
		t.Errorf("ForwardFor(nas):\n got %s\nwant %s", got, want)
	}
}

func TestIPv6Selectors(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{"fd3a:9c1e:44b0::6440:2", "fd3a:9c1e:44b0::6440:2/128"},
		{"fd3a:9c1e:44b0::/64", "fd3a:9c1e:44b0::/64"},
		{"::ffff:100.64.0.2", ""},
		{"fe80::1%eth0", ""},
	} {
		sel, err := ParseSelector(tc.raw, false)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: accepted as %v", tc.raw, sel)
			}
			continue
		}
		if err != nil || sel.Kind != SelCIDR || sel.Prefix.String() != tc.want {
			t.Errorf("%s = %v %v, want %s", tc.raw, sel, err, tc.want)
		}
	}
	for _, raw := range []string{"[fd3a:9c1e:44b0::6440:2]:22", "fd3a:9c1e:44b0::6440:2:22"} {
		d, err := ParseDst(raw)
		if err != nil || d.Host.Prefix.String() != "fd3a:9c1e:44b0::6440:2/128" || d.Ports[0].Lo != 22 {
			t.Errorf("ParseDst(%s) = %+v %v", raw, d, err)
		}
	}
}

func TestValidateIPv6OutsideOverlay(t *testing.T) {
	reg := Registry{Users: []string{"alice"}, Overlay: overlay, Overlay6: overlay6}
	for _, tc := range []struct{ dst, want string }{
		{"fd3a:9c1e:44b0::/64:*", ""},
		{"fd3a:9c1e:44b0::6440:2:22", ""},
		{"2001:db8::/32:*", "IPv6 subnet routes are not supported"},
		{"fd3a:9c1e::/48:*", "outside the IPv6 overlay"},
	} {
		doc := fmt.Sprintf("version: 1\nacls:\n  - action: accept\n    src: [alice]\n    dst: [%q]\n", tc.dst)
		p, err := Parse([]byte(doc))
		if err == nil {
			_, err = p.Validate(reg)
		}
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.dst, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %v, want %q", tc.dst, err, tc.want)
		}
	}
}
