package wg

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Filter protocols, matching the policy file.
const (
	ProtoAny  = "any"
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoICMP = "icmp"
)

// FilterRule lets packets from Src reach Dst (zero: this host) on the
// protocol and port range. ICMP rules ignore the ports.
type FilterRule struct {
	Src   netip.Prefix
	Dst   netip.Addr
	Proto string
	Lo    uint16
	Hi    uint16
}

// ForwardRule lets packets from Src reach the prefix Dst through this
// host, which forwards them as a subnet router or exit node (spec 013).
type ForwardRule struct {
	Src   netip.Prefix
	Dst   netip.Prefix
	Proto string
	Lo    uint16
	Hi    uint16
}

// FilterHook selects what the filter sees: everything arriving for
// this host (a client) or what the host forwards to other peers (the
// hub in front of static peers).
type FilterHook int

// Hooks.
const (
	HookInput FilterHook = iota
	HookForward
)

// FilterSet is the complete receiver-side filter: replies to accepted
// flows pass, ICMP and ICMPv6 echo from Visible passes, ICMPv6 errors
// and neighbour discovery pass, Rules open ports, everything else is
// dropped. Rules, forward rules and visible addresses may be of either
// family; a rule matches packets of its source's family.
type FilterSet struct {
	// Interface is the WireGuard interface the filter binds to.
	Interface string
	Hook      FilterHook
	// Local and Local6 are this host's overlay addresses (Local6 is zero
	// without the IPv6 overlay); on the forward hook packets for them
	// are not filtered.
	Local   netip.Addr
	Local6  netip.Addr
	Visible []netip.Addr
	Rules   []FilterRule
	// Forward opens the forwarding path for a router (spec 013): packets
	// arriving over the interface for an address that is not Local pass
	// only when a forward rule matches. Masquerade lists the destination
	// prefixes whose forwarded packets get this host's address on the
	// way out, for sources inside MasqueradeFrom (the overlay), or
	// MasqueradeFrom6 for an IPv6 destination (NAT66, spec 015); an
	// IPv6 destination without MasqueradeFrom6 is not masqueraded.
	Forward         []ForwardRule
	Masquerade      []netip.Prefix
	MasqueradeFrom  netip.Prefix
	MasqueradeFrom6 netip.Prefix
	// routerOnly skips the input chain (the userspace filter handles
	// it) and installs only the router chains.
	routerOnly bool
}

// locals lists the valid local addresses.
func (s FilterSet) locals() []netip.Addr {
	var out []netip.Addr
	for _, a := range []netip.Addr{s.Local, s.Local6} {
		if a.IsValid() {
			out = append(out, a)
		}
	}
	return out
}

// FilterStats are the counters shown in status.
type FilterStats struct {
	Rules int    `json:"rules"`
	Drops uint64 `json:"drops"`
	Flows int    `json:"flows"`
}

// Filterable is implemented by devices that can enforce a FilterSet.
type Filterable interface {
	SetFilter(ctx context.Context, set FilterSet) error
	FilterStats() FilterStats
}

// Flow lifetimes of the userspace filter.
const (
	flowUDP     = 120 * time.Second
	flowTCP     = time.Hour
	flowTCPDone = 30 * time.Second // after FIN or RST
	flowICMP    = 30 * time.Second
	sweepEvery  = 30 * time.Second
)

// IP protocol numbers.
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// packetFilter is the userspace filter between wireguard-go and the
// TUN: outbound packets record flows, inbound packets must match a
// flow, an ICMP diagnostic from a visible peer, an ICMPv6 error or
// neighbour discovery message, or a rule.
type packetFilter struct {
	now func() time.Time

	set atomic.Pointer[compiledFilter]

	mu        sync.Mutex
	flows     map[flowKey]time.Time
	lastSweep time.Time

	drops atomic.Uint64
}

type compiledFilter struct {
	hook    FilterHook
	local   netip.Addr
	local6  netip.Addr
	visible map[netip.Addr]bool
	rules   []FilterRule
	forward []ForwardRule
}

// flowKey identifies a flow from this host's point of view.
type flowKey struct {
	proto      uint8
	local      netip.Addr
	remote     netip.Addr
	localPort  uint16
	remotePort uint16
}

func newPacketFilter(now func() time.Time) *packetFilter {
	return &packetFilter{now: now, flows: map[flowKey]time.Time{}, lastSweep: now()}
}

// Set installs a filter set atomically for subsequent packets.
func (f *packetFilter) Set(set FilterSet) {
	c := &compiledFilter{hook: set.Hook, local: set.Local, local6: set.Local6, visible: make(map[netip.Addr]bool, len(set.Visible)), rules: append([]FilterRule(nil), set.Rules...), forward: append([]ForwardRule(nil), set.Forward...)}
	for _, a := range set.Visible {
		c.visible[a] = true
	}
	f.set.Store(c)
}

// Stats reports rule and flow counts and drops.
func (f *packetFilter) Stats() FilterStats {
	st := FilterStats{Drops: f.drops.Load()}
	if c := f.set.Load(); c != nil {
		st.Rules = len(c.rules)
	}
	f.mu.Lock()
	st.Flows = len(f.flows)
	f.mu.Unlock()
	return st
}

// packet is the decoded part of an IP packet the filter looks at.
type packet struct {
	proto    uint8
	src, dst netip.Addr
	sport    uint16 // ICMP, ICMPv6: type
	dport    uint16 // ICMP, ICMPv6: echo identifier
	tcpFlags uint8
}

// isICMP reports whether p is ICMP or ICMPv6, which have no ports.
func (p packet) isICMP() bool {
	return p.proto == protoICMP || p.proto == protoICMPv6
}

// parsePacket decodes an IPv4 or IPv6 packet; ok is false for anything
// malformed.
func parsePacket(b []byte) (packet, bool) {
	if len(b) == 0 {
		return packet{}, false
	}
	switch b[0] >> 4 {
	case 4:
		return parseIPv4(b)
	case 6:
		return parseIPv6(b)
	}
	return packet{}, false
}

// parseIPv4 decodes the headers; ok is false for anything that is not
// a well-formed IPv4 packet with a transport header the filter knows.
func parseIPv4(b []byte) (packet, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return packet{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return packet{}, false
	}
	p := packet{proto: b[9], src: netip.AddrFrom4([4]byte(b[12:16])), dst: netip.AddrFrom4([4]byte(b[16:20]))}
	// A fragment other than the first has no transport header.
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return p, true
	}
	return parseTransport(p, b[ihl:])
}

// IPv6 extension headers the filter walks past to the transport header.
const (
	ext6HopByHop = 0
	ext6Routing  = 43
	ext6Fragment = 44
	ext6DestOpts = 60
	// ext6Max bounds the walk; a real packet carries a handful at most.
	ext6Max = 8
)

// parseIPv6 decodes the fixed header, walks the hop-by-hop, routing,
// destination options and fragment headers, and decodes the transport
// header behind them. A fragment other than the first carries no
// transport header and is returned without ports, like an IPv4 one.
func parseIPv6(b []byte) (packet, bool) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return packet{}, false
	}
	p := packet{src: netip.AddrFrom16([16]byte(b[8:24])), dst: netip.AddrFrom16([16]byte(b[24:40]))}
	next, off := b[6], 40
	for range ext6Max {
		switch next {
		case ext6HopByHop, ext6Routing, ext6DestOpts:
			if len(b) < off+2 {
				return packet{}, false
			}
			next, off = b[off], off+(int(b[off+1])+1)*8
			continue
		case ext6Fragment:
			if len(b) < off+8 {
				return packet{}, false
			}
			fragOff := binary.BigEndian.Uint16(b[off+2:off+4]) >> 3
			next, off = b[off], off+8
			if fragOff != 0 {
				p.proto = next
				return p, true
			}
			continue
		}
		if len(b) < off {
			return packet{}, false
		}
		p.proto = next
		return parseTransport(p, b[off:])
	}
	return packet{}, false
}

// parseTransport fills p's ports, TCP flags or ICMP type and echo
// identifier from the transport header t.
func parseTransport(p packet, t []byte) (packet, bool) {
	switch p.proto {
	case protoTCP:
		if len(t) < 14 {
			return packet{}, false
		}
		p.sport, p.dport, p.tcpFlags = binary.BigEndian.Uint16(t[0:2]), binary.BigEndian.Uint16(t[2:4]), t[13]
	case protoUDP:
		if len(t) < 4 {
			return packet{}, false
		}
		p.sport, p.dport = binary.BigEndian.Uint16(t[0:2]), binary.BigEndian.Uint16(t[2:4])
	case protoICMP, protoICMPv6:
		if len(t) < 8 {
			return packet{}, false
		}
		p.sport = uint16(t[0])
		p.dport = binary.BigEndian.Uint16(t[4:6])
	}
	return p, true
}

// ICMP types the filter understands.
const (
	icmpEchoReply   = 0
	icmpUnreachable = 3
	icmpEchoRequest = 8
	icmpTimeExceed  = 11
	icmpParamProb   = 12

	// ICMPv6: errors 1 to 4 (unreachable, packet too big, time
	// exceeded, parameter problem), echo, and neighbour discovery 133
	// to 137 (router and neighbour solicitation and advertisement,
	// redirect).
	icmp6Unreachable   = 1
	icmp6ParamProb     = 4
	icmp6EchoRequest   = 128
	icmp6EchoReply     = 129
	icmp6RouterSolicit = 133
	icmp6Redirect      = 137
)

// echoRequest and echoReply are the echo types of p's ICMP family.
func (p packet) echoRequest() uint16 {
	if p.proto == protoICMPv6 {
		return icmp6EchoRequest
	}
	return icmpEchoRequest
}

func (p packet) echoReply() uint16 {
	if p.proto == protoICMPv6 {
		return icmp6EchoReply
	}
	return icmpEchoReply
}

// icmp6Always reports whether p is an ICMPv6 error or neighbour
// discovery message, which pass without a rule (spec 015).
func (p packet) icmp6Always() bool {
	return p.proto == protoICMPv6 && (p.sport >= icmp6Unreachable && p.sport <= icmp6ParamProb ||
		p.sport >= icmp6RouterSolicit && p.sport <= icmp6Redirect)
}

// Outbound records the flow of a packet this host sends.
func (f *packetFilter) Outbound(b []byte) {
	p, ok := parsePacket(b)
	if !ok {
		return
	}
	var ttl time.Duration
	key := flowKey{proto: p.proto, local: p.src, remote: p.dst}
	switch p.proto {
	case protoTCP:
		ttl = flowTCP
		if p.tcpFlags&0x05 != 0 { // FIN or RST
			ttl = flowTCPDone
		}
		key.localPort, key.remotePort = p.sport, p.dport
	case protoUDP:
		ttl = flowUDP
		key.localPort, key.remotePort = p.sport, p.dport
	case protoICMP, protoICMPv6:
		if p.sport != p.echoRequest() {
			return
		}
		ttl = flowICMP
		key.localPort = p.dport // echo identifier
	default:
		return
	}
	f.mu.Lock()
	f.flows[key] = f.now().Add(ttl)
	f.sweepLocked()
	f.mu.Unlock()
}

// Inbound reports whether a packet arriving for this host may pass.
func (f *packetFilter) Inbound(b []byte) bool {
	if f.allow(b) {
		return true
	}
	f.drops.Add(1)
	return false
}

func (f *packetFilter) allow(b []byte) bool {
	p, ok := parsePacket(b)
	if !ok {
		return false
	}
	c := f.set.Load()
	if c == nil {
		return f.reply(p)
	}
	if c.hook == HookForward && c.isLocal(p.dst) {
		return true
	}
	if f.reply(p) {
		return true
	}
	if c.hook == HookInput && c.local.IsValid() && !c.isLocal(p.dst) {
		// Not for this host: the kernel forwards it, so only a forward
		// rule may let it in (spec 013).
		return c.forwardAllows(p)
	}
	if p.icmp6Always() {
		return true
	}
	if c.visible[p.src] {
		switch {
		case p.proto == protoICMP && (p.sport == icmpEchoRequest || p.sport == icmpUnreachable || p.sport == icmpTimeExceed || p.sport == icmpParamProb),
			p.proto == protoICMPv6 && p.sport == icmp6EchoRequest:
			return true
		}
	}
	for i := range c.rules {
		r := &c.rules[i]
		if !r.Src.Contains(p.src) {
			continue
		}
		if r.Dst.IsValid() && r.Dst != p.dst {
			continue
		}
		if portsAllow(p, r.Proto, r.Lo, r.Hi) {
			return true
		}
	}
	return false
}

// isLocal reports whether a is one of this host's overlay addresses.
func (c *compiledFilter) isLocal(a netip.Addr) bool {
	return a == c.local || (c.local6.IsValid() && a == c.local6)
}

// forwardAllows reports whether a forward rule lets p through this
// host toward another network.
func (c *compiledFilter) forwardAllows(p packet) bool {
	for i := range c.forward {
		r := &c.forward[i]
		if !r.Src.Contains(p.src) || !r.Dst.Contains(p.dst) {
			continue
		}
		if portsAllow(p, r.Proto, r.Lo, r.Hi) {
			return true
		}
	}
	return false
}

// portsAllow applies a rule's protocol and port range to p. ICMP has
// no ports: an icmp rule, or an any-proto rule that opens every port,
// lets ICMP and ICMPv6 through.
func portsAllow(p packet, proto string, lo, hi uint16) bool {
	switch {
	case p.isICMP():
		return proto == ProtoICMP || (proto == ProtoAny && lo <= 1 && hi == 65535)
	case p.proto == protoTCP && (proto == ProtoTCP || proto == ProtoAny),
		p.proto == protoUDP && (proto == ProtoUDP || proto == ProtoAny):
		return p.dport >= lo && p.dport <= hi
	}
	return false
}

// reply reports whether p answers a flow this host opened and refreshes
// the flow.
func (f *packetFilter) reply(p packet) bool {
	key := flowKey{proto: p.proto, local: p.dst, remote: p.src}
	var ttl time.Duration
	switch p.proto {
	case protoTCP:
		key.localPort, key.remotePort = p.dport, p.sport
		ttl = flowTCP
		if p.tcpFlags&0x05 != 0 {
			ttl = flowTCPDone
		}
	case protoUDP:
		key.localPort, key.remotePort = p.dport, p.sport
		ttl = flowUDP
	case protoICMP, protoICMPv6:
		if p.sport != p.echoReply() {
			return false
		}
		key.localPort = p.dport
		ttl = flowICMP
	default:
		return false
	}
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, ok := f.flows[key]
	if !ok {
		return false
	}
	if !now.Before(exp) {
		delete(f.flows, key)
		return false
	}
	f.flows[key] = now.Add(ttl)
	return true
}

// sweepLocked drops expired flows every sweepEvery; mu held.
func (f *packetFilter) sweepLocked() {
	now := f.now()
	if now.Sub(f.lastSweep) < sweepEvery {
		return
	}
	f.lastSweep = now
	for k, exp := range f.flows {
		if !now.Before(exp) {
			delete(f.flows, k)
		}
	}
}
