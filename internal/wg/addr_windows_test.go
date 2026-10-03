package wg

import (
	"net/netip"
	"slices"
	"testing"
)

func TestWindowsAddressCommands(t *testing.T) {
	want := [][]string{
		{"interface", "ipv4", "set", "address", "name=thawr0", "static", "100.64.0.7", "255.192.0.0"},
		{"interface", "ipv6", "add", "address", "interface=thawr0", "address=fd00:1:2:3::6440:7/64", "store=active"},
		{"interface", "ipv4", "add", "address", "name=thawr0", "100.64.1.7", "255.255.255.0"},
	}
	got := addressCommands("thawr0", []netip.Prefix{
		netip.MustParsePrefix("100.64.0.7/10"),
		netip.MustParsePrefix("fd00:1:2:3::6440:7/64"),
		netip.MustParsePrefix("100.64.1.7/24"),
	})
	if !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("\n got %q\nwant %q", got, want)
	}
	for _, tc := range []struct {
		op, prefix string
		want       []string
	}{
		{"add", "10.1.0.0/24", []string{"interface", "ipv4", "add", "route", "10.1.0.0/24", "interface=thawr0", "metric=1", "store=active"}},
		{"add", "fd00:1:2:3::6440:9/128", []string{"interface", "ipv6", "add", "route", "fd00:1:2:3::6440:9/128", "interface=thawr0", "metric=1", "store=active"}},
		{"delete", "fd00:1:2:3::6440:9/128", []string{"interface", "ipv6", "delete", "route", "fd00:1:2:3::6440:9/128", "interface=thawr0", "store=active"}},
	} {
		if got := routeArgs(tc.op, "thawr0", netip.MustParsePrefix(tc.prefix)); !slices.Equal(got, tc.want) {
			t.Errorf("%s %s: %q, want %q", tc.op, tc.prefix, got, tc.want)
		}
	}
	if got := maskString(128); got != "255.255.255.255" {
		t.Errorf("maskString(128) = %s", got)
	}
}
