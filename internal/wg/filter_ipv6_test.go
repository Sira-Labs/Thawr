package wg

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// ext6 is one IPv6 extension header for mkPacket6: its type and the
// bytes after the next-header field.
type ext6 struct {
	kind uint8
	body []byte
}

// opts8 is a hop-by-hop, routing or destination options header of 8 bytes.
func opts8(kind uint8) ext6 { return ext6{kind, make([]byte, 7)} }

// frag is a fragment header with the given offset in 8-byte units.
func frag(offset uint16) ext6 {
	b := make([]byte, 7)
	binary.BigEndian.PutUint16(b[1:3], offset<<3|1)
	return ext6{ext6Fragment, b}
}

// mkPacket6 builds an IPv6 packet with the extension headers exts and
// a minimal transport header.
func mkPacket6(proto uint8, src, dst string, a, b uint16, tcpFlags uint8, exts ...ext6) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x60
	copy(pkt[8:24], netip.MustParseAddr(src).AsSlice())
	copy(pkt[24:40], netip.MustParseAddr(dst).AsSlice())
	next := &pkt[6]
	for _, e := range exts {
		*next = e.kind
		hdr := append([]byte{0}, e.body...)
		if e.kind != ext6Fragment {
			hdr[1] = byte(len(hdr)/8 - 1)
		}
		pkt = append(pkt, hdr...)
		next = &pkt[len(pkt)-len(hdr)]
	}
	*next = proto
	t := make([]byte, 20)
	switch proto {
	case protoTCP:
		binary.BigEndian.PutUint16(t[0:2], a)
		binary.BigEndian.PutUint16(t[2:4], b)
		t[12] = 0x50
		t[13] = tcpFlags
	case protoUDP:
		binary.BigEndian.PutUint16(t[0:2], a)
		binary.BigEndian.PutUint16(t[2:4], b)
	case protoICMPv6:
		t[0] = byte(a)
		binary.BigEndian.PutUint16(t[4:6], b)
	}
	pkt = append(pkt, t...)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)-40))
	return pkt
}

const (
	self6  = "fd00:1:2:3::6440:2"
	peerA6 = "fd00:1:2:3::6440:3"
	peerB6 = "fd00:1:2:3::6440:4"
)

func TestUserspaceFilterIPv6(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f := newPacketFilter(func() time.Time { return now })
	f.Set(FilterSet{
		Interface: "thawr0", Local: netip.MustParseAddr(self), Local6: netip.MustParseAddr(self6),
		Visible: []netip.Addr{netip.MustParseAddr(peerA), netip.MustParseAddr(peerA6)},
		Rules: []FilterRule{
			{Src: netip.MustParsePrefix(peerA + "/32"), Proto: ProtoTCP, Lo: 22, Hi: 22},
			{Src: netip.MustParsePrefix(peerA6 + "/128"), Proto: ProtoTCP, Lo: 22, Hi: 22},
			{Src: netip.MustParsePrefix("fd00:1:2:3::/64"), Proto: ProtoUDP, Lo: 53, Hi: 53},
			{Src: netip.MustParsePrefix(peerB6 + "/128"), Proto: ProtoICMP, Lo: 1, Hi: 65535},
		},
	})
	syn := uint8(0x02)
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"allowed tcp 22", mkPacket6(protoTCP, peerA6, self6, 40000, 22, syn), true},
		{"denied tcp 5432", mkPacket6(protoTCP, peerA6, self6, 40000, 5432, syn), false},
		{"prefix rule udp 53", mkPacket6(protoUDP, peerB6, self6, 5000, 53, 0), true},
		{"ipv4 rule does not open ipv6", mkPacket6(protoTCP, "fd00:1:2:3::6440:9", self6, 40000, 22, syn), false},
		{"echo request from visible", mkPacket6(protoICMPv6, peerA6, self6, icmp6EchoRequest, 7, 0), true},
		{"echo request from invisible", mkPacket6(protoICMPv6, "fd00:1:2:3::6440:9", self6, icmp6EchoRequest, 7, 0), false},
		{"icmp rule opens echo", mkPacket6(protoICMPv6, peerB6, self6, icmp6EchoRequest, 7, 0), true},
		{"unsolicited echo reply", mkPacket6(protoICMPv6, "fd00:1:2:3::6440:9", self6, icmp6EchoReply, 7, 0), false},
		{"packet too big from anyone", mkPacket6(protoICMPv6, "fd00:1:2:3::6440:9", self6, 2, 0, 0), true},
		{"unreachable", mkPacket6(protoICMPv6, "fd00:1:2:3::6440:9", self6, 1, 0, 0), true},
		{"parameter problem", mkPacket6(protoICMPv6, "fd00:1:2:3::6440:9", self6, 4, 0, 0), true},
		{"neighbour solicitation", mkPacket6(protoICMPv6, "fd00:1:2:3::6440:9", self6, 135, 0, 0), true},
		{"redirect", mkPacket6(protoICMPv6, "fd00:1:2:3::6440:9", self6, 137, 0, 0), true},
		{"other icmpv6 type", mkPacket6(protoICMPv6, "fd00:1:2:3::6440:9", self6, 138, 0, 0), false},
		{"hop-by-hop then tcp 22", mkPacket6(protoTCP, peerA6, self6, 40000, 22, syn, opts8(ext6HopByHop)), true},
		{"several headers then tcp 5432", mkPacket6(protoTCP, peerA6, self6, 40000, 5432, syn, opts8(ext6HopByHop), opts8(ext6Routing), opts8(ext6DestOpts)), false},
		{"several headers then tcp 22", mkPacket6(protoTCP, peerA6, self6, 40000, 22, syn, opts8(ext6DestOpts), opts8(ext6Routing)), true},
		{"first fragment tcp 22", mkPacket6(protoTCP, peerA6, self6, 40000, 22, syn, frag(0)), true},
		{"first fragment tcp 5432", mkPacket6(protoTCP, peerA6, self6, 40000, 5432, syn, frag(0)), false},
		{"later fragment", mkPacket6(protoTCP, peerA6, self6, 40000, 22, syn, frag(3)), false},
		{"truncated extension header", mkPacket6(protoTCP, peerA6, self6, 40000, 22, syn, opts8(ext6HopByHop))[:41], false},
		{"truncated transport", mkPacket6(protoTCP, peerA6, self6, 40000, 22, syn)[:45], false},
		{"too many extension headers", mkPacket6(protoTCP, peerA6, self6, 40000, 22, syn,
			opts8(ext6DestOpts), opts8(ext6DestOpts), opts8(ext6DestOpts), opts8(ext6DestOpts), opts8(ext6DestOpts),
			opts8(ext6DestOpts), opts8(ext6DestOpts), opts8(ext6DestOpts), opts8(ext6DestOpts)), false},
		{"short header", mkPacket6(protoTCP, peerA6, self6, 40000, 22, syn)[:39], false},
	}
	for _, tc := range cases {
		if got := f.Inbound(tc.pkt); got != tc.want {
			t.Errorf("%s: inbound = %v, want %v", tc.name, got, tc.want)
		}
	}

	// Replies to flows this host opened pass, per family.
	f.Outbound(mkPacket6(protoTCP, self6, peerB6, 51000, 443, syn))
	if !f.Inbound(mkPacket6(protoTCP, peerB6, self6, 443, 51000, 0x12)) {
		t.Error("SYN-ACK to our IPv6 connection dropped")
	}
	if f.Inbound(mkPacket(protoTCP, peerB, self, 443, 51000, 0x12)) {
		t.Error("an IPv6 flow opened the IPv4 path")
	}
	other := "fd00:1:2:3::6440:9"
	f.Outbound(mkPacket6(protoICMPv6, self6, other, icmp6EchoRequest, 99, 0))
	if !f.Inbound(mkPacket6(protoICMPv6, other, self6, icmp6EchoReply, 99, 0)) {
		t.Error("echo reply to our IPv6 request dropped")
	}
	if f.Inbound(mkPacket6(protoICMPv6, other, self6, icmp6EchoReply, 98, 0)) {
		t.Error("echo reply with another id accepted")
	}
}

func TestUserspaceFilterIPv6Forward(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f := newPacketFilter(func() time.Time { return now })
	f.Set(FilterSet{
		Interface: "thawr0", Local: netip.MustParseAddr(self), Local6: netip.MustParseAddr(self6),
		Forward: []ForwardRule{
			{Src: netip.MustParsePrefix(peerB6 + "/128"), Dst: netip.MustParsePrefix("::/0"), Proto: ProtoAny, Lo: 1, Hi: 65535},
		},
	})
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"exit node ipv6", mkPacket6(protoUDP, peerB6, "2001:db8::1", 5000, 53, 0), true},
		{"exit node icmpv6", mkPacket6(protoICMPv6, peerB6, "2001:db8::1", icmp6EchoRequest, 7, 0), true},
		{"other source", mkPacket6(protoUDP, peerA6, "2001:db8::1", 5000, 53, 0), false},
		{"ipv6 rule does not forward ipv4", mkPacket(protoUDP, peerB, "1.1.1.1", 5000, 53, 0), false},
		{"to this host still needs a rule", mkPacket6(protoUDP, peerB6, self6, 5000, 53, 0), false},
	}
	for _, tc := range cases {
		if got := f.Inbound(tc.pkt); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}

	// The hub's forward hook passes what is addressed to either of its
	// own addresses.
	hub := newPacketFilter(func() time.Time { return now })
	hub.Set(FilterSet{Hook: HookForward, Local: netip.MustParseAddr(self), Local6: netip.MustParseAddr(self6)})
	if !hub.Inbound(mkPacket6(protoTCP, peerA6, self6, 1, 9999, 0x02)) {
		t.Error("packet for the hub's IPv6 address filtered on the forward hook")
	}
	if hub.Inbound(mkPacket6(protoTCP, peerA6, peerB6, 1, 9999, 0x02)) {
		t.Error("forwarded IPv6 packet without a rule accepted")
	}
}
