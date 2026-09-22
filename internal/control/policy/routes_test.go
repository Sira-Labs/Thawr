package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

const routePolicy = `version: 1
groups:
  devs: [alice, bob]
acls:
  - action: accept
    src: [group:devs]
    dst: ["10.1.0.0/24:22", "10.2.0.0/16:*"]
  - action: accept
    src: [alice]
    dst: ["10.1.0.0/24:80,443"]
    proto: tcp
  - action: accept
    src: [markus]
    dst: ["internet:*"]
  - action: accept
    src: [alice]
    dst: ["100.64.0.2/32:*"]
`

var overlay = netip.MustParsePrefix("100.64.0.0/10")

func routePeers() []Peer {
	pfx := netip.MustParsePrefix
	return []Peer{
		{ID: "p1", Name: "markus-box", Owner: "markus", IPv4: ip("100.64.0.2")},
		{ID: "p2", Name: "alice-laptop", Owner: "alice", IPv4: ip("100.64.0.3")},
		{ID: "p3", Name: "bob-box", Owner: "bob", IPv4: ip("100.64.0.4")},
		// gw-a advertises the whole 10.0.0.0/8 and gw-b only 10.1.0.0/24.
		{ID: "p4", Name: "gw-a", Owner: "ops", IPv4: ip("100.64.0.5"), Routes: []netip.Prefix{pfx("10.0.0.0/8")}},
		{ID: "p5", Name: "gw-b", Owner: "ops", IPv4: ip("100.64.0.6"), Routes: []netip.Prefix{pfx("10.1.0.0/24")}},
		{ID: "p6", Name: "nas", Owner: "ops", IPv4: ip("100.64.0.7"), Routes: []netip.Prefix{ExitPrefix}},
		{ID: "p7", Name: "pending", Owner: "ops", IPv4: ip("100.64.0.8")},
	}
}

func compileRoutes(t *testing.T) *Compiled {
	t.Helper()
	p, err := Parse([]byte(routePolicy))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Validate(Registry{Users: []string{"alice", "bob", "markus"}, Overlay: overlay}); err != nil {
		t.Fatal(err)
	}
	return CompileWith(p, routePeers(), overlay)
}

func TestCompileForwardRules(t *testing.T) {
	c := compileRoutes(t)
	// gw-a serves both subnet prefixes; the rule's own prefix is what the
	// forward rule carries, with ports merged per protocol.
	got := fmt.Sprint(c.ForwardFor("p4"))
	want := fmt.Sprint([]ForwardRule{
		{Src: ip("100.64.0.3"), Dst: netip.MustParsePrefix("10.1.0.0/24"), Proto: ProtoAny, Lo: 22, Hi: 22},
		{Src: ip("100.64.0.3"), Dst: netip.MustParsePrefix("10.1.0.0/24"), Proto: ProtoTCP, Lo: 80, Hi: 80},
		{Src: ip("100.64.0.3"), Dst: netip.MustParsePrefix("10.1.0.0/24"), Proto: ProtoTCP, Lo: 443, Hi: 443},
		{Src: ip("100.64.0.3"), Dst: netip.MustParsePrefix("10.2.0.0/16"), Proto: ProtoAny, Lo: 1, Hi: 65535},
		{Src: ip("100.64.0.4"), Dst: netip.MustParsePrefix("10.1.0.0/24"), Proto: ProtoAny, Lo: 22, Hi: 22},
		{Src: ip("100.64.0.4"), Dst: netip.MustParsePrefix("10.2.0.0/16"), Proto: ProtoAny, Lo: 1, Hi: 65535},
	})
	if got != want {
		t.Errorf("ForwardFor(gw-a):\n got %s\nwant %s", got, want)
	}
	// gw-b advertises only the /24, so it never serves the /16.
	if rules := c.ForwardFor("p5"); len(rules) != 4 {
		t.Errorf("ForwardFor(gw-b) = %v", rules)
	}
	// The exit node serves internet rules only, for markus.
	if got := fmt.Sprint(c.ForwardFor("p6")); got != fmt.Sprint([]ForwardRule{{Src: ip("100.64.0.2"), Dst: ExitPrefix, Proto: ProtoAny, Lo: 1, Hi: 65535}}) {
		t.Errorf("ForwardFor(nas) = %s", got)
	}
	if c.ForwardFor("p7") != nil || c.ForwardFor("p2") != nil {
		t.Error("peers without routes have forward rules")
	}
}

func TestCompileRoutesVisibility(t *testing.T) {
	c := compileRoutes(t)
	// A route makes the router visible, and nothing else.
	if !c.Visible("p2", "p4") || !c.Visible("p4", "p2") || !c.Visible("p1", "p6") {
		t.Error("router not visible to a peer with a route through it")
	}
	if c.Allowed("p2", "p4") != nil || c.Allowed("p1", "p6") != nil {
		t.Error("a route opened a port on the router itself")
	}
	if c.Visible("p3", "p6") || c.Visible("p2", "p7") || c.Visible("p1", "p4") {
		t.Error("visible without a rule")
	}
	if c.FilterFor("p4") != nil {
		t.Errorf("router input filter: %v", c.FilterFor("p4"))
	}
}

func TestRoutesForOnePeerPerPrefix(t *testing.T) {
	c := compileRoutes(t)
	got := fmt.Sprint(c.RoutesFor("p2"))
	// Both gateways serve 10.1.0.0/24: the lowest peer id (p4) wins; the
	// /16 has one router.
	want := fmt.Sprint([]Route{
		{Prefix: netip.MustParsePrefix("10.1.0.0/24"), Via: "p4"},
		{Prefix: netip.MustParsePrefix("10.2.0.0/16"), Via: "p4"},
	})
	if got != want {
		t.Errorf("RoutesFor(alice):\n got %s\nwant %s", got, want)
	}
	if r := c.RoutesFor("p1"); len(r) != 0 {
		t.Errorf("markus has subnet routes: %v", r)
	}
	if e := c.ExitNodesFor("p1"); len(e) != 1 || e[0] != "p6" {
		t.Errorf("ExitNodesFor(markus) = %v", e)
	}
	if e := c.ExitNodesFor("p2"); len(e) != 0 {
		t.Errorf("alice has exit nodes: %v", e)
	}
	// The in-overlay CIDR still selects peers: alice reaches gw-a's box on
	// every port through the last rule, independent of routes.
	if !allows(c, "p2", "p1", "tcp", 22) {
		t.Error("in-overlay CIDR rule lost")
	}
}

func TestRoutesWithoutOverlay(t *testing.T) {
	p, err := Parse([]byte(routePolicy))
	if err != nil {
		t.Fatal(err)
	}
	c := Compile(p, routePeers())
	if len(c.RoutesFor("p2")) != 0 || len(c.ExitNodesFor("p1")) != 0 || c.Visible("p2", "p4") {
		t.Error("routes compiled without an overlay")
	}
}

func TestValidateRouteSelectors(t *testing.T) {
	reg := Registry{Users: []string{"alice", "bob", "markus"}, Overlay: overlay}
	cases := []struct {
		dst  string
		src  string
		want string
	}{
		{dst: "100.0.0.0/8:*", want: "overlaps the overlay"},
		{dst: "internet:*", want: ""},
		{dst: "10.0.0.0/8:22", want: ""},
		{dst: "100.64.1.0/24:22", want: ""},
		{src: "internet", dst: "*:*", want: "only valid in dst"},
	}
	for _, tc := range cases {
		src := "alice"
		if tc.src != "" {
			src = tc.src
		}
		doc := fmt.Sprintf("version: 1\nacls:\n  - action: accept\n    src: [%s]\n    dst: [%q]\n", src, tc.dst)
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
