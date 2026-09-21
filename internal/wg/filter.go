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
// flows pass, ICMP echo from Visible passes, Rules open ports,
// everything else is dropped.
type FilterSet struct {
	// Interface is the WireGuard interface the filter binds to.
	Interface string
	Hook      FilterHook
	// Local is this host's overlay address; on the forward hook packets
	// for it are not filtered.
	Local   netip.Addr
	Visible []netip.Addr
	Rules   []FilterRule
	// Forward opens the forwarding path for a router (spec 013): packets
	// arriving over the interface for an address that is not Local pass
	// only when a forward rule matches. Masquerade lists the destination
	// prefixes whose forwarded packets get this host's address on the
	// way out, for sources inside MasqueradeFrom (the overlay).
	Forward        []ForwardRule
	Masquerade     []netip.Prefix
	MasqueradeFrom netip.Prefix
	// routerOnly skips the input chain (the userspace filter handles
	// it) and installs only the router chains.
	routerOnly bool
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
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

// packetFilter is the userspace filter between wireguard-go and the
// TUN: outbound packets record flows, inbound packets must match a
// flow, an ICMP diagnostic from a visible peer or a rule.
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
	c := &compiledFilter{hook: set.Hook, local: set.Local, visible: make(map[netip.Addr]bool, len(set.Visible)), rules: append([]FilterRule(nil), set.Rules...), forward: append([]ForwardRule(nil), set.Forward...)}
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

// packet is the decoded part of an IPv4 packet the filter looks at.
type packet struct {
	proto    uint8
	src, dst netip.Addr
	sport    uint16 // ICMP: type
	dport    uint16 // ICMP: identifier
	tcpFlags uint8
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
	t := b[ihl:]
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
	case protoICMP:
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
)

// Outbound records the flow of a packet this host sends.
func (f *packetFilter) Outbound(b []byte) {
	p, ok := parseIPv4(b)
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
	case protoICMP:
		if p.sport != icmpEchoRequest {
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
	p, ok := parseIPv4(b)
	if !ok {
		return false
	}
	c := f.set.Load()
	if c == nil {
		return f.reply(p)
	}
	if c.hook == HookForward && p.dst == c.local {
		return true
	}
	if f.reply(p) {
		return true
	}
	if c.hook == HookInput && c.local.IsValid() && p.dst != c.local {
		// Not for this host: the kernel forwards it, so only a forward
		// rule may let it in (spec 013).
		return c.forwardAllows(p)
	}
	if p.proto == protoICMP && c.visible[p.src] {
		switch p.sport {
		case icmpEchoRequest, icmpUnreachable, icmpTimeExceed, icmpParamProb:
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
		switch {
		case p.proto == protoICMP:
			// ICMP has no ports: an icmp rule or an any-proto rule that
			// opens every port lets it through.
			if r.Proto == ProtoICMP || (r.Proto == ProtoAny && r.Lo <= 1 && r.Hi == 65535) {
				return true
			}
		case p.proto == protoTCP && (r.Proto == ProtoTCP || r.Proto == ProtoAny),
			p.proto == protoUDP && (r.Proto == ProtoUDP || r.Proto == ProtoAny):
			if p.dport >= r.Lo && p.dport <= r.Hi {
				return true
			}
		}
	}
	return false
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

// portsAllow applies a rule's protocol and port range to p.
func portsAllow(p packet, proto string, lo, hi uint16) bool {
	switch {
	case p.proto == protoICMP:
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
	case protoICMP:
		if p.sport != icmpEchoReply {
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
