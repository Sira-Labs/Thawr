package wg

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestExitRouteParts(t *testing.T) {
	for _, def := range []netip.Prefix{ExitRoute, ExitRoute6} {
		route, rules := exitRouteParts(7, def)
		family := unix.AF_INET
		if def.Addr().Is6() {
			family = unix.AF_INET6
		}
		if route.Family != family || route.Table != exitTable || route.LinkIndex != 7 || route.Dst.String() != def.String() {
			t.Errorf("%s: route %+v", def, route)
		}
		if len(rules) != 2 {
			t.Fatalf("%s: %d rules", def, len(rules))
		}
		main, mark := rules[0], rules[1]
		if main.Family != family || main.Table != unix.RT_TABLE_MAIN || main.SuppressPrefixlen != 0 || main.Priority != exitRulePriority {
			t.Errorf("%s: main rule %+v", def, main)
		}
		if mark.Family != family || mark.Table != exitTable || mark.Mark != DefaultFwMark || !mark.Invert || mark.Priority != exitRulePriority+1 {
			t.Errorf("%s: mark rule %+v", def, mark)
		}
	}
	if !IsExitRoute(ExitRoute) || !IsExitRoute(ExitRoute6) || IsExitRoute(netip.MustParsePrefix("10.0.0.0/8")) {
		t.Error("IsExitRoute")
	}
}

// fakeProc writes a sysctl tree under a temporary directory: path ->
// value, relative to /proc/sys/net.
func fakeProc(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, value := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func readProc(t *testing.T, root, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestEnableIPv6ForwardAcceptRA(t *testing.T) {
	root := fakeProc(t, map[string]string{
		"ipv4/ip_forward":               "0",
		"ipv6/conf/all/forwarding":      "0",
		"ipv6/conf/all/accept_ra":       "1",
		"ipv6/conf/default/accept_ra":   "1",
		"ipv6/conf/eth0/accept_ra":      "1",
		"ipv6/conf/eth1/accept_ra":      "0",
		"ipv6/conf/wlan0/accept_ra":     "2",
		"ipv6/conf/lo/accept_ra":        "1",
		"ipv6/conf/thawr0/disable_ipv6": "1",
	})
	undo, err := enableIPForward(root)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"ipv4/ip_forward":             "1",
		"ipv6/conf/all/forwarding":    "1",
		"ipv6/conf/all/accept_ra":     "1",
		"ipv6/conf/default/accept_ra": "2",
		"ipv6/conf/eth0/accept_ra":    "2",
		"ipv6/conf/eth1/accept_ra":    "0",
		"ipv6/conf/wlan0/accept_ra":   "2",
		"ipv6/conf/lo/accept_ra":      "2",
	} {
		if got := readProc(t, root, name); got != want {
			t.Errorf("after enable %s = %s, want %s", name, got, want)
		}
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"ipv4/ip_forward":             "0",
		"ipv6/conf/all/forwarding":    "0",
		"ipv6/conf/default/accept_ra": "1",
		"ipv6/conf/eth0/accept_ra":    "1",
		"ipv6/conf/wlan0/accept_ra":   "2",
		"ipv6/conf/lo/accept_ra":      "1",
	} {
		if got := readProc(t, root, name); got != want {
			t.Errorf("after undo %s = %s, want %s", name, got, want)
		}
	}
}

func TestEnableIPv6ForwardAlreadyOnOrAbsent(t *testing.T) {
	// Forwarding already on: whoever turned it on owns accept_ra.
	root := fakeProc(t, map[string]string{
		"ipv6/conf/all/forwarding": "1",
		"ipv6/conf/eth0/accept_ra": "1",
	})
	undo, err := enableIPv6Forward(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if got := readProc(t, root, "ipv6/conf/eth0/accept_ra"); got != "1" {
		t.Errorf("accept_ra touched: %s", got)
	}
	if got := readProc(t, root, "ipv6/conf/all/forwarding"); got != "1" {
		t.Errorf("forwarding turned off by undo: %s", got)
	}

	// A kernel without IPv6 has no ipv6 tree; IPv4 forwarding still works.
	root = fakeProc(t, map[string]string{"ipv4/ip_forward": "0"})
	undo, err = enableIPForward(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := readProc(t, root, "ipv4/ip_forward"); got != "1" {
		t.Errorf("ip_forward = %s", got)
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if got := readProc(t, root, "ipv4/ip_forward"); got != "0" {
		t.Errorf("ip_forward after undo = %s", got)
	}
}

func TestEnableIPv6ForwardRollsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	root := fakeProc(t, map[string]string{
		"ipv6/conf/all/forwarding": "0",
		"ipv6/conf/eth0/accept_ra": "1",
	})
	// A read-only switch makes the final write fail; accept_ra must be
	// back to 1.
	if err := os.Chmod(filepath.Join(root, "ipv6/conf/all/forwarding"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := enableIPv6Forward(root); err == nil {
		t.Fatal("enable succeeded with a read-only switch")
	}
	if got := readProc(t, root, "ipv6/conf/eth0/accept_ra"); got != "1" {
		t.Errorf("accept_ra not rolled back: %s", got)
	}
}

func TestEnableInterfaceIPv6(t *testing.T) {
	root := fakeProc(t, map[string]string{"ipv6/conf/thawr0/disable_ipv6": "1"})
	if err := enableInterfaceIPv6(root, "thawr0"); err != nil {
		t.Fatal(err)
	}
	if got := readProc(t, root, "ipv6/conf/thawr0/disable_ipv6"); got != "0" {
		t.Errorf("disable_ipv6 = %s", got)
	}
	if err := enableInterfaceIPv6(root, "missing0"); err != nil {
		t.Errorf("an interface without the setting: %v", err)
	}
}

func TestPrefixMatchFamilies(t *testing.T) {
	cases := []struct {
		prefix string
		mask   []byte
	}{
		{"100.64.0.0/10", []byte{0xff, 0xc0, 0, 0}},
		{"fd00:1:2:3::/64", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"fd00::/12", []byte{0xff, 0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}
	for _, tc := range cases {
		p := netip.MustParsePrefix(tc.prefix)
		if got := prefixMask(p.Bits(), p.Addr().BitLen()); string(got) != string(tc.mask) {
			t.Errorf("%s: mask %x, want %x", tc.prefix, got, tc.mask)
		}
		if n := len(prefixMatch(p)); n != 2 {
			t.Errorf("%s: %d expressions, want mask and compare", tc.prefix, n)
		}
	}
	for _, host := range []string{"100.64.0.7/32", "fd00::6440:7/128"} {
		if n := len(prefixMatch(netip.MustParsePrefix(host))); n != 1 {
			t.Errorf("%s: %d expressions, want one compare", host, n)
		}
	}
	if got := protocolsOf(FilterRule{Proto: ProtoAny, Lo: 1, Hi: 65535}, true); len(got) != 3 || got[2] != unix.IPPROTO_ICMPV6 {
		t.Errorf("any-proto IPv6 protocols %v", got)
	}
	if got := protocolsOf(FilterRule{Proto: ProtoICMP}, false); len(got) != 1 || got[0] != unix.IPPROTO_ICMP {
		t.Errorf("icmp IPv4 protocols %v", got)
	}
}
