package control

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// IPv6For is a peer's IPv6 overlay address (spec 015): prefix, a /64,
// with the peer's IPv4 overlay address in its last 32 bits, so
// 100.64.0.7 becomes <prefix>::6440:7. IPv4 and IPv6 addresses always
// come in pairs, and no second allocator is needed. It returns the zero
// Addr when prefix is not an IPv6 /64 or v4 is not IPv4.
func IPv6For(prefix netip.Prefix, v4 netip.Addr) netip.Addr {
	v4 = v4.Unmap()
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Bits() != 64 || !v4.Is4() {
		return netip.Addr{}
	}
	b := prefix.Masked().Addr().As16()
	four := v4.As4()
	copy(b[12:], four[:])
	return netip.AddrFrom16(b)
}

// ErrNoRandom means the random source failed while generating a prefix.
var ErrNoRandom = errors.New("control: no randomness for the IPv6 overlay prefix")

// NewULAPrefix generates a unique local /64 as RFC 4193 describes: fd,
// a 40-bit random global ID read from rnd, and subnet 0.
func NewULAPrefix(rnd io.Reader) (netip.Prefix, error) {
	var b [16]byte
	b[0] = 0xfd
	if _, err := io.ReadFull(rnd, b[1:6]); err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %w", ErrNoRandom, err)
	}
	return netip.PrefixFrom(netip.AddrFrom16(b), 64), nil
}

// addrString is a.String(), or "" for the zero Addr (which String
// renders as "invalid IP").
func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
