package control

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

func TestIPv6For(t *testing.T) {
	ula := netip.MustParsePrefix("fd3a:9c1e:44b0::/64")
	cases := []struct {
		name   string
		prefix netip.Prefix
		v4     string
		want   string
	}{
		{"peer", ula, "100.64.0.7", "fd3a:9c1e:44b0::6440:7"},
		{"hub", ula, "100.64.0.1", "fd3a:9c1e:44b0::6440:1"},
		{"top of /10", ula, "100.127.255.254", "fd3a:9c1e:44b0::647f:fffe"},
		{"mapped v4", ula, "::ffff:100.64.0.7", "fd3a:9c1e:44b0::6440:7"},
		{"host bits in prefix ignored", netip.MustParsePrefix("fd3a:9c1e:44b0::99/64"), "100.64.0.7", "fd3a:9c1e:44b0::6440:7"},
		{"not a /64", netip.MustParsePrefix("fd3a:9c1e::/48"), "100.64.0.7", ""},
		{"ipv4 prefix", netip.MustParsePrefix("100.64.0.0/10"), "100.64.0.7", ""},
		{"ipv6 peer", ula, "fd00::7", ""},
		{"no prefix", netip.Prefix{}, "100.64.0.7", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IPv6For(tc.prefix, netip.MustParseAddr(tc.v4))
			if tc.want == "" {
				if got.IsValid() {
					t.Errorf("IPv6For = %s, want none", got)
				}
				return
			}
			if got != netip.MustParseAddr(tc.want) {
				t.Errorf("IPv6For = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestNewULAPrefix(t *testing.T) {
	p, err := NewULAPrefix(bytes.NewReader([]byte{0x3a, 0x9c, 0x1e, 0x44, 0xb0, 0xff}))
	if err != nil {
		t.Fatal(err)
	}
	if p.String() != "fd3a:9c1e:44b0::/64" {
		t.Errorf("prefix = %s", p)
	}
	if _, err := NewULAPrefix(bytes.NewReader([]byte{1, 2})); !errors.Is(err, ErrNoRandom) {
		t.Errorf("short source: %v", err)
	}
}
