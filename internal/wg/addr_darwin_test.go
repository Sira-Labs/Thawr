package wg

import (
	"net/netip"
	"slices"
	"testing"
)

func TestDarwinAddressCommands(t *testing.T) {
	cases := []struct {
		prefix string
		want   [][]string
	}{
		{"100.64.0.7/10", [][]string{
			{"ifconfig", "utun4", "inet", "100.64.0.7", "100.64.0.7", "netmask", "255.192.0.0", "alias"},
			{"route", "-q", "-n", "add", "-inet", "100.64.0.0/10", "-interface", "utun4"},
		}},
		{"fd00:1:2:3::6440:7/64", [][]string{
			{"ifconfig", "utun4", "inet6", "fd00:1:2:3::6440:7", "prefixlen", "64", "alias"},
			{"route", "-q", "-n", "add", "-inet6", "fd00:1:2:3::/64", "-interface", "utun4"},
		}},
	}
	for _, tc := range cases {
		got := addressCommands("utun4", netip.MustParsePrefix(tc.prefix))
		if !slices.EqualFunc(got, tc.want, slices.Equal[[]string]) {
			t.Errorf("%s:\n got %q\nwant %q", tc.prefix, got, tc.want)
		}
	}
	if got, want := routeCommand("delete", "utun4", netip.MustParsePrefix("fd00:1:2:3::6440:9/128")),
		[]string{"route", "-q", "-n", "delete", "-inet6", "fd00:1:2:3::6440:9/128", "-interface", "utun4"}; !slices.Equal(got, want) {
		t.Errorf("route delete: %q, want %q", got, want)
	}
	if got := maskString(64); got != "255.255.255.255" {
		t.Errorf("maskString(64) = %s", got)
	}
}
