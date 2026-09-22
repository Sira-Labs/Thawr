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
	if set.Hook == HookForward && set.Local.IsValid() {
		add(append(ipv4(), daddr(), &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: set.Local.AsSlice()}, accept)...)
	}
	// Replies to accepted flows.
	add(&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)}, accept)
	// ICMP echo from visible peers.
	if len(set.Visible) > 0 {
		visible := &nftables.Set{Table: table, Anonymous: true, Constant: true, KeyType: nftables.TypeIPAddr}
		elems := make([]nftables.SetElement, 0, len(set.Visible))
		for _, a := range set.Visible {
			if a.Is4() {
				elems = append(elems, nftables.SetElement{Key: a.AsSlice()})
			}
		}
		if len(elems) > 0 {
			if err := c.AddSet(visible, elems); err == nil {
				add(append(ipv4(), saddr(), &expr.Lookup{SourceRegister: 1, SetName: visible.Name, SetID: visible.ID},
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMP}},
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{8}},
					accept)...)
			}
		}
	}
	count := 0
	for _, r := range set.Rules {
		for _, proto := range protocolsOf(r) {
			exprs := append(ipv4(), saddr())
			if r.Src.Bits() == 32 {
				exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: r.Src.Addr().AsSlice()})
			} else {
				mask := netip.PrefixFrom(r.Src.Addr(), r.Src.Bits())
				exprs = append(exprs, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: prefixMask(mask.Bits()), Xor: []byte{0, 0, 0, 0}},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: r.Src.Masked().Addr().AsSlice()})
			}
			if r.Dst.IsValid() {
				exprs = append(exprs, daddr(), &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: r.Dst.AsSlice()})
			}
			exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}})
			if proto != unix.IPPROTO_ICMP {
				exprs = append(exprs, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
				if r.Lo == r.Hi {
					exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Lo)})
				} else {
					exprs = append(exprs, &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: binaryutil.BigEndian.PutUint16(r.Lo), ToData: binaryutil.BigEndian.PutUint16(r.Hi)})
				}
			}
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
	add(&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)}, accept)
	count := 0
	for _, r := range set.Forward {
		for _, proto := range protocolsOf(FilterRule{Proto: r.Proto, Lo: r.Lo, Hi: r.Hi}) {
			exprs := []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: iface}}
			exprs = append(exprs, ipv4()...)
			exprs = append(exprs, saddr())
			exprs = append(exprs, prefixMatch(r.Src)...)
			if r.Dst.Bits() > 0 {
				exprs = append(exprs, daddr())
				exprs = append(exprs, prefixMatch(r.Dst)...)
			}
			exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}})
			if proto != unix.IPPROTO_ICMP {
				exprs = append(exprs, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
				if r.Lo == r.Hi {
					exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Lo)})
				} else {
					exprs = append(exprs, &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: binaryutil.BigEndian.PutUint16(r.Lo), ToData: binaryutil.BigEndian.PutUint16(r.Hi)})
				}
			}
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
		exprs := []expr.Any{&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: iface}}
		exprs = append(exprs, ipv4()...)
		if set.MasqueradeFrom.IsValid() {
			exprs = append(exprs, saddr())
			exprs = append(exprs, prefixMatch(set.MasqueradeFrom)...)
		}
		if dst.Bits() > 0 {
			exprs = append(exprs, daddr())
			exprs = append(exprs, prefixMatch(dst)...)
		}
		c.AddRule(&nftables.Rule{Table: table, Chain: nat, Exprs: append(exprs, &expr.Masq{})})
	}
	return count
}

// prefixMatch compares the address in register 1 with p.
func prefixMatch(p netip.Prefix) []expr.Any {
	if p.Bits() == 32 {
		return []expr.Any{&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Addr().AsSlice()}}
	}
	return []expr.Any{&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: prefixMask(p.Bits()), Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Masked().Addr().AsSlice()}}
}

// protocolsOf expands a rule's protocol into IP protocol numbers.
func protocolsOf(r FilterRule) []byte {
	switch r.Proto {
	case ProtoTCP:
		return []byte{unix.IPPROTO_TCP}
	case ProtoUDP:
		return []byte{unix.IPPROTO_UDP}
	case ProtoICMP:
		return []byte{unix.IPPROTO_ICMP}
	default:
		out := []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP}
		if r.Lo <= 1 && r.Hi == 65535 {
			out = append(out, unix.IPPROTO_ICMP)
		}
		return out
	}
}

// ipv4 matches IPv4 packets, which the inet table also sees for IPv6.
func ipv4() []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}}}
}

// saddr loads the IPv4 source address into register 1.
func saddr() expr.Any {
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}
}

func daddr() expr.Any {
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}
}

// ifname encodes an interface name as nftables expects: 16 bytes,
// NUL padded.
func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

func prefixMask(bits int) []byte {
	m := ^uint32(0) << (32 - uint(bits))
	return binaryutil.BigEndian.PutUint32(m)
}
