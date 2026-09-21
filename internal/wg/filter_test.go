package wg

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// mkPacket builds an IPv4 packet with a minimal transport header.
func mkPacket(proto uint8, src, dst string, a, b uint16, tcpFlags uint8) []byte {
	pkt := make([]byte, 20+20)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = proto
	copy(pkt[12:16], netip.MustParseAddr(src).AsSlice())
	copy(pkt[16:20], netip.MustParseAddr(dst).AsSlice())
	t := pkt[20:]
	switch proto {
	case protoTCP:
		binary.BigEndian.PutUint16(t[0:2], a)
		binary.BigEndian.PutUint16(t[2:4], b)
		t[12] = 0x50
		t[13] = tcpFlags
	case protoUDP:
		binary.BigEndian.PutUint16(t[0:2], a)
		binary.BigEndian.PutUint16(t[2:4], b)
	case protoICMP:
		t[0] = byte(a)
		binary.BigEndian.PutUint16(t[4:6], b)
	}
	return pkt
}

const (
	self  = "100.64.0.2"
	peerA = "100.64.0.3"
	peerB = "100.64.0.4"
)

func TestUserspaceFilter(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	f := newPacketFilter(func() time.Time { return now })
	f.Set(FilterSet{
		Interface: "thawr0", Local: netip.MustParseAddr(self),
		Visible: []netip.Addr{netip.MustParseAddr(peerA)},
		Rules: []FilterRule{
			{Src: netip.MustParsePrefix(peerA + "/32"), Proto: ProtoTCP, Lo: 22, Hi: 22},
			{Src: netip.MustParsePrefix(peerA + "/32"), Proto: ProtoAny, Lo: 8000, Hi: 8100},
		},
	})
	syn := uint8(0x02)
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"allowed tcp 22", mkPacket(protoTCP, peerA, self, 40000, 22, syn), true},
		{"denied tcp 5432", mkPacket(protoTCP, peerA, self, 40000, 5432, syn), false},
		{"any-proto range udp", mkPacket(protoUDP, peerA, self, 5000, 8050, 0), true},
		{"any-proto range tcp", mkPacket(protoTCP, peerA, self, 5000, 8100, syn), true},
		{"outside range", mkPacket(protoUDP, peerA, self, 5000, 8101, 0), false},
		{"unknown source", mkPacket(protoTCP, peerB, self, 40000, 22, syn), false},
		{"echo request from visible", mkPacket(protoICMP, peerA, self, icmpEchoRequest, 7, 0), true},
		{"echo request from invisible", mkPacket(protoICMP, peerB, self, icmpEchoRequest, 7, 0), false},
		{"unsolicited echo reply", mkPacket(protoICMP, peerA, self, icmpEchoReply, 7, 0), false},
		{"unreachable from visible", mkPacket(protoICMP, peerA, self, icmpUnreachable, 0, 0), true},
		{"not ipv4", []byte{0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
		{"truncated", mkPacket(protoTCP, peerA, self, 1, 22, syn)[:25], false},
	}
	for _, tc := range cases {
		if got := f.Inbound(tc.pkt); got != tc.want {
			t.Errorf("%s: inbound = %v, want %v", tc.name, got, tc.want)
		}
	}
	drops := f.Stats().Drops
	if drops != 7 {
		t.Errorf("drops = %d, want 7", drops)
	}

	// Replies to flows this host opened pass, even from invisible peers.
	f.Outbound(mkPacket(protoTCP, self, peerB, 51000, 443, syn))
	if !f.Inbound(mkPacket(protoTCP, peerB, self, 443, 51000, 0x12)) {
		t.Error("SYN-ACK to our connection dropped")
	}
	if f.Inbound(mkPacket(protoTCP, peerB, self, 443, 51001, 0x12)) {
		t.Error("reply to a different local port accepted")
	}
	f.Outbound(mkPacket(protoUDP, self, peerB, 5353, 53, 0))
	if !f.Inbound(mkPacket(protoUDP, peerB, self, 53, 5353, 0)) {
		t.Error("UDP reply dropped")
	}
	now = now.Add(flowUDP + time.Second)
	if f.Inbound(mkPacket(protoUDP, peerB, self, 53, 5353, 0)) {
		t.Error("UDP reply accepted after the idle timeout")
	}
	// TCP flows live an hour unless closed.
	if !f.Inbound(mkPacket(protoTCP, peerB, self, 443, 51000, 0x10)) {
		t.Error("TCP reply dropped after 2 minutes")
	}
	f.Inbound(mkPacket(protoTCP, peerB, self, 443, 51000, 0x11)) // FIN shortens the flow
	now = now.Add(flowTCPDone + time.Second)
	if f.Inbound(mkPacket(protoTCP, peerB, self, 443, 51000, 0x10)) {
		t.Error("TCP flow still open 30 s after FIN")
	}
	// Our own echo request opens the way for the reply.
	f.Outbound(mkPacket(protoICMP, self, peerB, icmpEchoRequest, 99, 0))
	if !f.Inbound(mkPacket(protoICMP, peerB, self, icmpEchoReply, 99, 0)) {
		t.Error("echo reply to our request dropped")
	}
	if f.Inbound(mkPacket(protoICMP, peerB, self, icmpEchoReply, 98, 0)) {
		t.Error("echo reply with another id accepted")
	}
	if st := f.Stats(); st.Rules != 2 || st.Flows == 0 {
		t.Errorf("stats: %+v", st)
	}
}

func TestFilterForwardHookAndDst(t *testing.T) {
	now := time.Now()
	f := newPacketFilter(func() time.Time { return now })
	static := "100.64.0.20"
	f.Set(FilterSet{Hook: HookForward, Local: netip.MustParseAddr(self),
		Rules: []FilterRule{{Src: netip.MustParsePrefix("100.64.0.0/24"), Dst: netip.MustParseAddr(static), Proto: ProtoTCP, Lo: 443, Hi: 443}}})
	if !f.Inbound(mkPacket(protoTCP, peerA, self, 1, 9999, 0x02)) {
		t.Error("packet for the hub itself filtered on the forward hook")
	}
	if !f.Inbound(mkPacket(protoTCP, peerA, static, 1, 443, 0x02)) {
		t.Error("allowed forwarded packet dropped")
	}
	if f.Inbound(mkPacket(protoTCP, peerA, static, 1, 80, 0x02)) || f.Inbound(mkPacket(protoTCP, peerA, "100.64.0.21", 1, 443, 0x02)) {
		t.Error("forwarded packet outside the rule accepted")
	}
	// Without any set only replies pass.
	g := newPacketFilter(func() time.Time { return now })
	if g.Inbound(mkPacket(protoTCP, peerA, self, 1, 22, 0x02)) {
		t.Error("unset filter accepted a packet")
	}
	g.Outbound(mkPacket(protoUDP, self, peerA, 1000, 2000, 0))
	if !g.Inbound(mkPacket(protoUDP, peerA, self, 2000, 1000, 0)) {
		t.Error("unset filter dropped a reply")
	}
}

func TestUserspaceFilterForward(t *testing.T) {
	now := time.Date(2026, 9, 22, 1, 0, 0, 0, time.UTC)
	f := newPacketFilter(func() time.Time { return now })
	f.Set(FilterSet{
		Interface: "thawr0", Local: netip.MustParseAddr(self),
		Forward: []ForwardRule{
			{Src: netip.MustParsePrefix(peerA + "/32"), Dst: netip.MustParsePrefix("10.1.0.0/24"), Proto: ProtoAny, Lo: 22, Hi: 22},
			{Src: netip.MustParsePrefix(peerB + "/32"), Dst: netip.MustParsePrefix("0.0.0.0/0"), Proto: ProtoAny, Lo: 1, Hi: 65535},
		},
	})
	syn := uint8(0x02)
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"forward allowed", mkPacket(protoTCP, peerA, "10.1.0.20", 40000, 22, syn), true},
		{"forward wrong port", mkPacket(protoTCP, peerA, "10.1.0.20", 40000, 80, syn), false},
		{"forward outside prefix", mkPacket(protoTCP, peerA, "10.2.0.20", 40000, 22, syn), false},
		{"exit node any", mkPacket(protoUDP, peerB, "1.1.1.1", 5000, 53, 0), true},
		{"exit node icmp", mkPacket(protoICMP, peerB, "1.1.1.1", icmpEchoRequest, 7, 0), true},
		{"not a forwarder for A to internet", mkPacket(protoUDP, peerA, "1.1.1.1", 5000, 53, 0), false},
		{"to this host still needs a rule", mkPacket(protoTCP, peerA, self, 40000, 22, syn), false},
	}
	for _, tc := range cases {
		if got := f.Inbound(tc.pkt); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	// The LAN host's reply, read from the TUN, opens the return path for
	// the rest of the flow.
	f.Outbound(mkPacket(protoTCP, "10.1.0.20", peerA, 22, 40000, 0x12))
	if !f.Inbound(mkPacket(protoTCP, peerA, "10.1.0.20", 40000, 22, 0x10)) {
		t.Error("established forward flow dropped")
	}
}
