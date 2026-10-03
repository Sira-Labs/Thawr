//go:build integration && linux

package wg

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestNftablesRuleset installs a filter set and compares the listing
// with what the policy demands. Needs root and the nft binary.
func TestNftablesRuleset(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft binary not found")
	}
	var f nftFilter
	set := FilterSet{Interface: "thawrtest", Local: netip.MustParseAddr("100.64.0.2"),
		Visible: []netip.Addr{netip.MustParseAddr("100.64.0.3"), netip.MustParseAddr("100.64.0.4")},
		Rules: []FilterRule{
			{Src: netip.MustParsePrefix("100.64.0.3/32"), Proto: ProtoTCP, Lo: 22, Hi: 22},
			{Src: netip.MustParsePrefix("100.64.0.0/24"), Proto: ProtoAny, Lo: 8000, Hi: 8100},
			{Src: netip.MustParsePrefix("100.64.0.4/32"), Proto: ProtoICMP, Lo: 1, Hi: 65535},
		}}
	if err := f.SetFilter(context.Background(), set); err != nil {
		t.Fatalf("SetFilter: %v", err)
	}
	defer func() {
		if err := f.remove(); err != nil {
			t.Errorf("remove: %v", err)
		}
	}()
	out, err := exec.CommandContext(context.Background(), "nft", "list", "table", "inet", "thawr").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v\n%s", err, out)
	}
	listing := string(out)
	// nft 1.0.x prints `tcp dport 22`; older releases print the same
	// rule as `meta l4proto tcp th dport 22`. Either rendering is fine.
	for _, want := range [][]string{
		{`type filter hook input priority filter; policy drop;`},
		{`iifname != "thawrtest" accept`},
		{`ct state established,related accept`},
		{`icmp type echo-request accept`},
		{`ip saddr 100.64.0.3 tcp dport 22 accept`, `ip saddr 100.64.0.3 meta l4proto tcp th dport 22 accept`},
		{`ip saddr 100.64.0.0/24 tcp dport 8000-8100 accept`, `ip saddr 100.64.0.0/24 meta l4proto tcp th dport 8000-8100 accept`},
		{`ip saddr 100.64.0.0/24 udp dport 8000-8100 accept`, `ip saddr 100.64.0.0/24 meta l4proto udp th dport 8000-8100 accept`},
		{`ip saddr 100.64.0.4 meta l4proto icmp accept`},
		{`counter packets 0 bytes 0 drop`},
	} {
		found := false
		for _, w := range want {
			found = found || strings.Contains(listing, w)
		}
		if !found {
			t.Errorf("ruleset lacks %q:\n%s", want[0], listing)
		}
	}
	if st := f.FilterStats(); st.Rules != 4 {
		t.Errorf("stats: %+v", st)
	}
	// Replacing the set leaves exactly one copy of each rule.
	set.Rules = set.Rules[:1]
	if err := f.SetFilter(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	out, _ = exec.CommandContext(context.Background(), "nft", "list", "table", "inet", "thawr").CombinedOutput()
	// Interface, established, two ICMPv6 rules, echo, one policy rule.
	if strings.Count(string(out), "accept") != 6 || strings.Contains(string(out), "8000-8100") {
		t.Errorf("ruleset not replaced atomically:\n%s", out)
	}
}

// TestNftablesRulesetIPv6 installs a dual-stack filter set with router
// chains and checks the IPv6 rules and NAT66 (spec 015).
func TestNftablesRulesetIPv6(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft binary not found")
	}
	var f nftFilter
	set := FilterSet{Interface: "thawrtest", Local: netip.MustParseAddr("100.64.0.2"), Local6: netip.MustParseAddr("fd00:1:2:3::6440:2"),
		Visible: []netip.Addr{netip.MustParseAddr("100.64.0.3"), netip.MustParseAddr("fd00:1:2:3::6440:3")},
		Rules: []FilterRule{
			{Src: netip.MustParsePrefix("100.64.0.3/32"), Proto: ProtoTCP, Lo: 22, Hi: 22},
			{Src: netip.MustParsePrefix("fd00:1:2:3::6440:3/128"), Proto: ProtoTCP, Lo: 22, Hi: 22},
			{Src: netip.MustParsePrefix("fd00:1:2:3::/64"), Proto: ProtoUDP, Lo: 53, Hi: 53},
			{Src: netip.MustParsePrefix("fd00:1:2:3::6440:4/128"), Proto: ProtoICMP, Lo: 1, Hi: 65535},
		},
		Forward: []ForwardRule{
			{Src: netip.MustParsePrefix("100.64.0.3/32"), Dst: netip.MustParsePrefix("0.0.0.0/0"), Proto: ProtoAny, Lo: 1, Hi: 65535},
			{Src: netip.MustParsePrefix("fd00:1:2:3::6440:3/128"), Dst: netip.MustParsePrefix("::/0"), Proto: ProtoAny, Lo: 1, Hi: 65535},
		},
		Masquerade:      []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		MasqueradeFrom:  netip.MustParsePrefix("100.64.0.0/10"),
		MasqueradeFrom6: netip.MustParsePrefix("fd00:1:2:3::/64"),
	}
	if err := f.SetFilter(context.Background(), set); err != nil {
		t.Fatalf("SetFilter: %v", err)
	}
	defer func() {
		if err := f.remove(); err != nil {
			t.Errorf("remove: %v", err)
		}
	}()
	out, err := exec.CommandContext(context.Background(), "nft", "list", "table", "inet", "thawr").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v\n%s", err, out)
	}
	listing := string(out)
	for _, want := range [][]string{
		{`icmpv6 type 1-4 accept`, `icmpv6 type { destination-unreachable-parameter-problem } accept`},
		{`icmpv6 type 133-137 accept`},
		{`ip saddr { 100.64.0.3 } icmp type echo-request accept`, `ip saddr 100.64.0.3 icmp type echo-request accept`},
		{`ip6 saddr { fd00:1:2:3::6440:3 } icmpv6 type echo-request accept`, `ip6 saddr fd00:1:2:3::6440:3 icmpv6 type echo-request accept`},
		{`ip6 saddr fd00:1:2:3::6440:3 tcp dport 22 accept`, `ip6 saddr fd00:1:2:3::6440:3 meta l4proto tcp th dport 22 accept`},
		{`ip6 saddr fd00:1:2:3::/64 udp dport 53 accept`, `ip6 saddr fd00:1:2:3::/64 meta l4proto udp th dport 53 accept`},
		{`ip6 saddr fd00:1:2:3::6440:4 meta l4proto ipv6-icmp accept`, `ip6 saddr fd00:1:2:3::6440:4 meta l4proto icmpv6 accept`},
		{`iifname "thawrtest" ip6 saddr fd00:1:2:3::6440:3 meta l4proto tcp`, `iifname "thawrtest" ip6 saddr fd00:1:2:3::6440:3 tcp`},
		{`oifname != "thawrtest" ip saddr 100.64.0.0/10 masquerade`},
		{`oifname != "thawrtest" ip6 saddr fd00:1:2:3::/64 masquerade`},
	} {
		found := false
		for _, w := range want {
			found = found || strings.Contains(listing, w)
		}
		if !found {
			t.Errorf("ruleset lacks %q:\n%s", want[0], listing)
		}
	}

	// The hub's forward hook lets traffic for both of its own addresses
	// through unfiltered.
	hub := FilterSet{Interface: "thawrtest", Hook: HookForward, Local: netip.MustParseAddr("100.64.0.1"), Local6: netip.MustParseAddr("fd00:1:2:3::6440:1")}
	if err := f.SetFilter(context.Background(), hub); err != nil {
		t.Fatal(err)
	}
	out, _ = exec.CommandContext(context.Background(), "nft", "list", "table", "inet", "thawr").CombinedOutput()
	for _, want := range []string{`ip daddr 100.64.0.1 accept`, `ip6 daddr fd00:1:2:3::6440:1 accept`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("forward hook lacks %q:\n%s", want, out)
		}
	}
}
