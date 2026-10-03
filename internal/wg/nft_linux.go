package wg

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// nftTable is the table the kernel filter lives in.
const nftTable = "thawr"

// nftFilter enforces a FilterSet with nftables for the kernel adapter.
// Every SetFilter replaces the whole table in one atomic batch, so
// there is never a moment with rules missing or everything accepted.
type nftFilter struct {
	mu        sync.Mutex
	installed bool
	rules     int
	chain     string
}

// SetFilter installs set, replacing the previous ruleset atomically.
func (n *nftFilter) SetFilter(_ context.Context, set FilterSet) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("wg: nftables: %w", err)
	}
	chain, count := buildRuleset(c, set)
	if err := c.Flush(); err != nil {
		return fmt.Errorf("wg: install nftables filter: %w", err)
	}
	n.installed, n.rules, n.chain = true, count, chain
	return nil
}

// FilterStats reads the drop counter from the last rule of the chain.
func (n *nftFilter) FilterStats() FilterStats {
	n.mu.Lock()
	defer n.mu.Unlock()
	st := FilterStats{Rules: n.rules}
	if !n.installed {
		return st
	}
	c, err := nftables.New()
	if err != nil {
		return st
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: nftTable}
	rules, err := c.GetRules(table, &nftables.Chain{Name: n.chain, Table: table})
	if err != nil {
		return st
	}
	for _, r := range rules {
		for _, e := range r.Exprs {
			if cnt, ok := e.(*expr.Counter); ok {
				st.Drops = cnt.Packets
			}
		}
	}
	return st
}

// remove deletes the table; called when the device closes.
func (n *nftFilter) remove() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.installed {
		return nil
	}
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("wg: nftables: %w", err)
	}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTable})
	if err := c.Flush(); err != nil {
		return fmt.Errorf("wg: remove nftables filter: %w", err)
	}
	n.installed = false
	return nil
}

// buildRuleset queues the complete table into c and returns the chain
// name and the number of policy rules.
func buildRuleset(c *nftables.Conn, set FilterSet) (string, int) {
	table := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTable})
	c.FlushTable(table)
	if set.routerOnly {
		return "forward", buildRouterChains(c, table, set)
	}
	drop := nftables.ChainPolicyDrop
	name, hook, ifKey := "input", nftables.ChainHookInput, expr.MetaKeyIIFNAME
	if set.Hook == HookForward {
		name, hook, ifKey = "forward", nftables.ChainHookForward, expr.MetaKeyOIFNAME
	}
	chain := c.AddChain(&nftables.Chain{Name: name, Table: table, Type: nftables.ChainTypeFilter, Hooknum: hook, Priority: nftables.ChainPriorityFilter, Policy: &drop})
	add := func(exprs ...expr.Any) {
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	}
	accept := &expr.Verdict{Kind: expr.VerdictAccept}

	// Traffic not crossing the WireGuard interface is none of our business.
	add(&expr.Meta{Key: ifKey, Register: 1}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(set.Interface)}, accept)
	if set.Hook == HookForward {
		for _, local := range set.locals() {
			add(append(family(local), daddr(local), &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: local.AsSlice()}, accept)...)
		}
	}
	// Replies to accepted flows.
	add(established()...)
	// ICMPv6 errors and neighbour discovery, without which path MTU
	// discovery breaks (spec 015).
	for _, types := range [][2]byte{{icmp6Unreachable, icmp6ParamProb}, {icmp6RouterSolicit, icmp6Redirect}} {
		add(append(family(netip.IPv6Unspecified()),
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{types[0]}, ToData: []byte{types[1]}},
			accept)...)
	}
	// ICMP echo from visible peers.
	addVisible(c, table, set.Visible, add)
	count := 0
	for _, r := range set.Rules {
		if !r.Src.IsValid() || (r.Dst.IsValid() && r.Dst.Is6() != r.Src.Addr().Is6()) {
			continue
		}
		for _, proto := range protocolsOf(r, r.Src.Addr().Is6()) {
			exprs := append(family(r.Src.Addr()), saddr(r.Src.Addr()))
			exprs = append(exprs, prefixMatch(r.Src)...)
			if r.Dst.IsValid() {
				exprs = append(exprs, daddr(r.Dst), &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: r.Dst.AsSlice()})
			}
			exprs = append(exprs, protoPorts(proto, r.Lo, r.Hi)...)
			add(append(exprs, accept)...)
			count++
		}
	}
	// Count what the policy drops.
	add(&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})
	if set.Hook == HookInput && (len(set.Forward) > 0 || len(set.Masquerade) > 0) {
		count += buildRouterChains(c, table, set)
	}
	return name, count
}

// addVisible adds the rules accepting ICMP and ICMPv6 echo requests
// from the visible addresses, one anonymous set per family.
func addVisible(c *nftables.Conn, table *nftables.Table, visible []netip.Addr, add func(...expr.Any)) {
	for _, fam := range []struct {
		zero    netip.Addr
		keyType nftables.SetDatatype
		proto   byte
		echo    byte
	}{
		{netip.IPv4Unspecified(), nftables.TypeIPAddr, unix.IPPROTO_ICMP, icmpEchoRequest},
		{netip.IPv6Unspecified(), nftables.TypeIP6Addr, unix.IPPROTO_ICMPV6, icmp6EchoRequest},
	} {
		var elems []nftables.SetElement
		for _, a := range visible {
			if a.Is4() == fam.zero.Is4() && !a.Is4In6() {
				elems = append(elems, nftables.SetElement{Key: a.AsSlice()})
			}
		}
		if len(elems) == 0 {
			continue
		}
		set := &nftables.Set{Table: table, Anonymous: true, Constant: true, KeyType: fam.keyType}
		if err := c.AddSet(set, elems); err != nil {
			continue
		}
		add(append(family(fam.zero), saddr(fam.zero), &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{fam.proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{fam.echo}},
			&expr.Verdict{Kind: expr.VerdictAccept})...)
	}
}

// established matches packets of flows conntrack already accepted.
func established() []expr.Any {
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Verdict{Kind: expr.VerdictAccept}}
}

// protoPorts matches the transport protocol and, unless it is ICMP or
// ICMPv6, the destination port range.
func protoPorts(proto byte, lo, hi uint16) []expr.Any {
	exprs := []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}}
	if proto == unix.IPPROTO_ICMP || proto == unix.IPPROTO_ICMPV6 {
		return exprs
	}
	exprs = append(exprs, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
	if lo == hi {
		return append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(lo)})
	}
	return append(exprs, &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: binaryutil.BigEndian.PutUint16(lo), ToData: binaryutil.BigEndian.PutUint16(hi)})
}

// buildRouterChains adds what a subnet router or exit node needs next
// to its input chain (spec 013): a forward chain that drops everything
// crossing the tunnel unless a forward rule or an established flow
// allows it, and a nat chain that masquerades forwarded packets on the
// way out. Traffic between the host's other interfaces is untouched.
func buildRouterChains(c *nftables.Conn, table *nftables.Table, set FilterSet) int {
	drop := nftables.ChainPolicyDrop
	fwd := c.AddChain(&nftables.Chain{Name: "forward", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &drop})
	add := func(exprs ...expr.Any) {
		c.AddRule(&nftables.Rule{Table: table, Chain: fwd, Exprs: exprs})
	}
	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	iface := ifname(set.Interface)
	// Neither in nor out over the tunnel: none of our business.
	add(&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: iface},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: iface}, accept)
	add(established()...)
	count := 0
	for _, r := range set.Forward {
		if !r.Src.IsValid() || !r.Dst.IsValid() || r.Dst.Addr().Is6() != r.Src.Addr().Is6() {
			continue
		}
		for _, proto := range protocolsOf(FilterRule{Proto: r.Proto, Lo: r.Lo, Hi: r.Hi}, r.Src.Addr().Is6()) {
			exprs := []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: iface}}
			exprs = append(exprs, family(r.Src.Addr())...)
			exprs = append(exprs, saddr(r.Src.Addr()))
			exprs = append(exprs, prefixMatch(r.Src)...)
			if r.Dst.Bits() > 0 {
				exprs = append(exprs, daddr(r.Dst.Addr()))
				exprs = append(exprs, prefixMatch(r.Dst)...)
			}
			exprs = append(exprs, protoPorts(proto, r.Lo, r.Hi)...)
			add(append(exprs, accept)...)
			count++
		}
	}
	add(&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})
	if len(set.Masquerade) == 0 {
		return count
	}
	nat := c.AddChain(&nftables.Chain{Name: "postrouting", Table: table, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource})
	for _, dst := range set.Masquerade {
		from := set.MasqueradeFrom
		if dst.Addr().Is6() {
			// NAT66 for an exit node (spec 015). Without the overlay's
			// IPv6 prefix every IPv6 packet leaving the host would be
			// rewritten, so there is no rule at all.
			from = set.MasqueradeFrom6
			if !from.IsValid() {
				continue
			}
		}
		exprs := []expr.Any{&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: iface}}
		exprs = append(exprs, family(dst.Addr())...)
		if from.IsValid() && from.Addr().Is6() == dst.Addr().Is6() {
			exprs = append(exprs, saddr(from.Addr()))
			exprs = append(exprs, prefixMatch(from)...)
		}
		if dst.Bits() > 0 {
			exprs = append(exprs, daddr(dst.Addr()))
			exprs = append(exprs, prefixMatch(dst)...)
		}
		c.AddRule(&nftables.Rule{Table: table, Chain: nat, Exprs: append(exprs, &expr.Masq{})})
	}
	return count
}

// prefixMatch compares the address in register 1 with p, of either
// family.
func prefixMatch(p netip.Prefix) []expr.Any {
	if p.Bits() == p.Addr().BitLen() {
		return []expr.Any{&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Addr().AsSlice()}}
	}
	n := uint32(4)
	if p.Addr().Is6() {
		n = 16
	}
	return []expr.Any{&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: n, Mask: prefixMask(p.Bits(), p.Addr().BitLen()), Xor: make([]byte, n)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Masked().Addr().AsSlice()}}
}

// protocolsOf expands a rule's protocol into IP protocol numbers; an
// ICMP rule means ICMPv6 for an IPv6 source.
func protocolsOf(r FilterRule, v6 bool) []byte {
	icmp := byte(unix.IPPROTO_ICMP)
	if v6 {
		icmp = unix.IPPROTO_ICMPV6
	}
	switch r.Proto {
	case ProtoTCP:
		return []byte{unix.IPPROTO_TCP}
	case ProtoUDP:
		return []byte{unix.IPPROTO_UDP}
	case ProtoICMP:
		return []byte{icmp}
	default:
		out := []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP}
		if r.Lo <= 1 && r.Hi == 65535 {
			out = append(out, icmp)
		}
		return out
	}
}

// family matches packets of a's family, which the inet table sees both
// of.
func family(a netip.Addr) []expr.Any {
	proto := byte(unix.NFPROTO_IPV4)
	if a.Is6() {
		proto = unix.NFPROTO_IPV6
	}
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}}
}

// saddr loads the source address of a's family into register 1.
func saddr(a netip.Addr) expr.Any {
	if a.Is6() {
		return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16}
	}
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}
}

// daddr loads the destination address of a's family into register 1.
func daddr(a netip.Addr) expr.Any {
	if a.Is6() {
		return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16}
	}
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}
}

// ifname encodes an interface name as nftables expects: 16 bytes,
// NUL padded.
func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

// prefixMask is the network mask of a prefix length in an address of
// bitLen bits, big endian.
func prefixMask(bits, bitLen int) []byte {
	m := make([]byte, bitLen/8)
	for i := range m {
		switch {
		case bits >= 8:
			m[i] = 0xff
			bits -= 8
		case bits > 0:
			m[i] = ^byte(0) << (8 - bits)
			bits = 0
		}
	}
	return m
}
