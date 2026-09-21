package policy

import (
	"net/netip"
	"sort"
)

// Peer is what compilation needs to know about a registered peer.
type Peer struct {
	ID    string
	Name  string
	Owner string // user name; empty for ownerless peers
	Tags  []string
	IPv4  netip.Addr
	// Routes are the prefixes the peer advertises and an admin approved
	// (spec 013); 0.0.0.0/0 makes it an exit node.
	Routes []netip.Prefix
}

// PortRule is one allowed (proto, port range) between two peers.
type PortRule struct {
	Proto string
	Lo    uint16
	Hi    uint16
}

// FilterRule allows Src to reach the destination on a port range; it
// is what the netmap carries to the receiving peer.
type FilterRule struct {
	Src   netip.Addr
	Proto string
	Lo    uint16
	Hi    uint16
}

// ForwardRule allows Src to reach Dst through the router on a port
// range; the router installs it on its forwarding path (spec 013).
type ForwardRule struct {
	Src   netip.Addr
	Dst   netip.Prefix
	Proto string
	Lo    uint16
	Hi    uint16
}

// Route is one prefix a peer reaches through the router Via (a peer id).
type Route struct {
	Prefix netip.Prefix
	Via    string
}

// ExitPrefix is the route an exit node advertises.
var ExitPrefix = netip.MustParsePrefix("0.0.0.0/0")

// Summary describes a compiled policy in one line.
type Summary struct {
	Rules        int `json:"rules"`
	Peers        int `json:"peers"`
	VisiblePairs int `json:"visible_pairs"`
}

// Compiled is a policy evaluated against a peer list. It is immutable
// and safe for concurrent use.
type Compiled struct {
	Hash  string
	peers []Peer
	index map[string]int
	rules []crule
	// routeRules are the dst entries naming a subnet or the internet.
	routeRules []rrule
	// tagOwners maps tag:name to the set of user names that may use it.
	tagOwners map[string]map[string]bool
	summary   Summary
}

// crule is one (rule, dst entry) pair with resolved bitsets.
type crule struct {
	src   bitset
	dst   bitset
	self  bool
	proto string
	ports []PortRange
}

// rrule is one (rule, route dst) pair: the sources that may reach the
// prefix through any router advertising it. internet marks
// "internet:*", served by exit nodes only.
type rrule struct {
	src      bitset
	prefix   netip.Prefix
	internet bool
	proto    string
	ports    []PortRange
}

type bitset []uint64

func newBitset(n int) bitset { return make(bitset, (n+63)/64) }

func (b bitset) set(i int)      { b[i/64] |= 1 << (uint(i) % 64) }
func (b bitset) has(i int) bool { return b[i/64]&(1<<(uint(i)%64)) != 0 }

// Compile resolves every selector against peers with no overlay known,
// so every CIDR selects peers (the pre-013 behaviour).
func Compile(p *Policy, peers []Peer) *Compiled {
	return CompileWith(p, peers, netip.Prefix{})
}

// CompileWith resolves every selector against peers. A dst CIDR outside
// overlay is a subnet route and "internet" an exit-node grant; with an
// invalid overlay both are ignored. Unknown names resolve to nothing
// (Validate reports them separately).
func CompileWith(p *Policy, peers []Peer, overlay netip.Prefix) *Compiled {
	c := &Compiled{Hash: p.Hash, peers: append([]Peer(nil), peers...), index: make(map[string]int, len(peers)), tagOwners: map[string]map[string]bool{}}
	for i, pe := range c.peers {
		c.index[pe.ID] = i
	}
	groups := make(map[string]map[string]bool, len(p.Groups))
	for name, members := range p.Groups {
		groups[name] = set(members)
	}
	resolve := func(sel Selector) bitset {
		b := newBitset(len(peers))
		for i, pe := range peers {
			switch sel.Kind {
			case SelAny:
				b.set(i)
			case SelUser:
				if pe.Owner != "" && pe.Owner == sel.Name {
					b.set(i)
				}
			case SelGroup:
				if pe.Owner != "" && groups[sel.Name][pe.Owner] {
					b.set(i)
				}
			case SelTag:
				for _, t := range pe.Tags {
					if t == "tag:"+sel.Name {
						b.set(i)
					}
				}
			case SelPeer:
				if pe.Name == sel.Name {
					b.set(i)
				}
			case SelCIDR:
				if pe.IPv4.IsValid() && sel.Prefix.Contains(pe.IPv4) {
					b.set(i)
				}
			case SelSelf, SelInternet:
			}
		}
		return b
	}
	union := func(sels []Selector) bitset {
		b := newBitset(len(peers))
		for _, s := range sels {
			for i, w := range resolve(s) {
				b[i] |= w
			}
		}
		return b
	}
	for _, r := range p.rules {
		src := union(r.src)
		for _, d := range r.dst {
			switch {
			case d.Host.Kind == SelInternet:
				if overlay.IsValid() {
					c.routeRules = append(c.routeRules, rrule{src: src, prefix: ExitPrefix, internet: true, proto: r.proto, ports: d.Ports})
				}
				continue
			case d.Host.Kind == SelCIDR && IsRoute(d.Host.Prefix, overlay):
				c.routeRules = append(c.routeRules, rrule{src: src, prefix: d.Host.Prefix, proto: r.proto, ports: d.Ports})
				continue
			}
			cr := crule{src: src, proto: r.proto, ports: d.Ports}
			if d.Host.Kind == SelSelf {
				cr.self = true
			} else {
				cr.dst = resolve(d.Host)
			}
			c.rules = append(c.rules, cr)
		}
	}
	for tag, owners := range p.TagOwners {
		allowed := map[string]bool{}
		for _, o := range owners {
			sel, err := ParseSelector(o, false)
			if err != nil {
				continue
			}
			switch sel.Kind {
			case SelUser:
				allowed[sel.Name] = true
			case SelGroup:
				for u := range groups[sel.Name] {
					allowed[u] = true
				}
			default:
			}
		}
		c.tagOwners[tag] = allowed
	}
	c.summary = Summary{Rules: len(p.ACLs), Peers: len(peers)}
	for i := range peers {
		for j := i + 1; j < len(peers); j++ {
			if c.visibleIdx(i, j) {
				c.summary.VisiblePairs++
			}
		}
	}
	return c
}

// IsRoute reports whether a dst prefix names a subnet route: it lies
// entirely outside the overlay. A prefix inside the overlay selects
// peers; one that contains the overlay is neither (Validate rejects it).
func IsRoute(prefix, overlay netip.Prefix) bool {
	return overlay.IsValid() && prefix.IsValid() && !prefix.Overlaps(overlay)
}

// matches reports whether rule r lets src reach dst (indices).
func (c *Compiled) matches(r *crule, src, dst int) bool {
	if !r.src.has(src) {
		return false
	}
	if r.self {
		a, b := c.peers[src], c.peers[dst]
		return a.Owner != "" && a.Owner == b.Owner && src != dst
	}
	return r.dst.has(dst)
}

// serves reports whether router j carries the prefix of route rule r:
// an exit node serves internet rules, a subnet router serves rules
// whose prefix lies inside one it advertises.
func (c *Compiled) serves(r *rrule, j int) bool {
	for _, adv := range c.peers[j].Routes {
		if r.internet {
			if adv == ExitPrefix {
				return true
			}
			continue
		}
		if adv != ExitPrefix && adv.Bits() <= r.prefix.Bits() && adv.Contains(r.prefix.Addr()) {
			return true
		}
	}
	return false
}

// Allowed returns the union of port rules letting src reach dst, merged
// per protocol; nil when nothing is allowed. Routes through dst do not
// count: they open nothing on the router itself.
func (c *Compiled) Allowed(src, dst string) []PortRule {
	i, ok := c.index[src]
	j, ok2 := c.index[dst]
	if !ok || !ok2 || i == j {
		return nil
	}
	return c.allowedIdx(i, j)
}

func (c *Compiled) allowedIdx(i, j int) []PortRule {
	byProto := map[string][]PortRange{}
	for r := range c.rules {
		if c.matches(&c.rules[r], i, j) {
			byProto[c.rules[r].proto] = append(byProto[c.rules[r].proto], c.rules[r].ports...)
		}
	}
	var out []PortRule
	for _, proto := range []string{ProtoAny, ProtoTCP, ProtoUDP, ProtoICMP} {
		for _, pr := range mergeRanges(byProto[proto]) {
			out = append(out, PortRule{Proto: proto, Lo: pr.Lo, Hi: pr.Hi})
		}
	}
	return out
}

func (c *Compiled) anyIdx(i, j int) bool {
	for r := range c.rules {
		if c.matches(&c.rules[r], i, j) {
			return true
		}
	}
	return c.forwardAny(i, j)
}

// forwardAny reports whether i may reach anything through router j.
func (c *Compiled) forwardAny(i, j int) bool {
	if i == j {
		return false
	}
	for r := range c.routeRules {
		if c.routeRules[r].src.has(i) && c.serves(&c.routeRules[r], j) {
			return true
		}
	}
	return false
}

func (c *Compiled) visibleIdx(i, j int) bool { return c.anyIdx(i, j) || c.anyIdx(j, i) }

// Visible reports whether a and b may exchange keys: at least one
// direction allows something, a route through the other included.
// Symmetric by construction.
func (c *Compiled) Visible(a, b string) bool {
	i, ok := c.index[a]
	j, ok2 := c.index[b]
	if !ok || !ok2 || i == j {
		return false
	}
	return c.visibleIdx(i, j)
}

// FilterFor lists, for every peer that may reach dst, the allowed
// protocol and port ranges by source address. ICMP echo between visible
// peers is implicit and not listed.
func (c *Compiled) FilterFor(dst string) []FilterRule {
	j, ok := c.index[dst]
	if !ok {
		return nil
	}
	var out []FilterRule
	for i, src := range c.peers {
		if i == j || !src.IPv4.IsValid() {
			continue
		}
		for _, pr := range c.allowedIdx(i, j) {
			out = append(out, FilterRule{Src: src.IPv4, Proto: pr.Proto, Lo: pr.Lo, Hi: pr.Hi})
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Src.Less(out[b].Src) })
	return out
}

// ForwardFor lists the rules router installs on its forwarding path:
// every source that may reach a prefix through it, with the rule's own
// prefix (not the advertised one) and ports, merged per protocol.
func (c *Compiled) ForwardFor(router string) []ForwardRule {
	j, ok := c.index[router]
	if !ok {
		return nil
	}
	type key struct {
		src   netip.Addr
		dst   netip.Prefix
		proto string
	}
	byKey := map[key][]PortRange{}
	var order []key
	for i, src := range c.peers {
		if i == j || !src.IPv4.IsValid() {
			continue
		}
		for r := range c.routeRules {
			rr := &c.routeRules[r]
			if !rr.src.has(i) || !c.serves(rr, j) {
				continue
			}
			k := key{src.IPv4, rr.prefix, rr.proto}
			if _, seen := byKey[k]; !seen {
				order = append(order, k)
			}
			byKey[k] = append(byKey[k], rr.ports...)
		}
	}
	var out []ForwardRule
	for _, k := range order {
		for _, pr := range mergeRanges(byKey[k]) {
			out = append(out, ForwardRule{Src: k.src, Dst: k.dst, Proto: k.proto, Lo: pr.Lo, Hi: pr.Hi})
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Src != out[b].Src {
			return out[a].Src.Less(out[b].Src)
		}
		return out[a].Dst.String() < out[b].Dst.String()
	})
	return out
}

// RoutesFor lists the subnet prefixes src may reach and the router each
// goes through. A prefix advertised by several routers is assigned to
// the one with the lowest peer id, so a client puts it on one WireGuard
// peer only. Exit nodes are not routes; see ExitNodesFor.
func (c *Compiled) RoutesFor(src string) []Route {
	i, ok := c.index[src]
	if !ok {
		return nil
	}
	via := map[netip.Prefix]string{}
	for r := range c.routeRules {
		rr := &c.routeRules[r]
		if rr.internet || !rr.src.has(i) {
			continue
		}
		for j := range c.peers {
			if j == i || !c.serves(rr, j) {
				continue
			}
			if cur, ok := via[rr.prefix]; !ok || c.peers[j].ID < cur {
				via[rr.prefix] = c.peers[j].ID
			}
		}
	}
	out := make([]Route, 0, len(via))
	for p, id := range via {
		out = append(out, Route{Prefix: p, Via: id})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Prefix.String() < out[b].Prefix.String() })
	return out
}

// ExitNodesFor lists the peer ids src may use as exit node, sorted.
func (c *Compiled) ExitNodesFor(src string) []string {
	i, ok := c.index[src]
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for r := range c.routeRules {
		rr := &c.routeRules[r]
		if !rr.internet || !rr.src.has(i) {
			continue
		}
		for j := range c.peers {
			if j != i && c.serves(rr, j) && !seen[c.peers[j].ID] {
				seen[c.peers[j].ID] = true
				out = append(out, c.peers[j].ID)
			}
		}
	}
	sort.Strings(out)
	return out
}

// MayUseTag reports whether user may create tokens carrying tag
// ("tag:name"). Tags with no tagOwners entry belong to nobody.
func (c *Compiled) MayUseTag(user, tag string) bool {
	return c.tagOwners[tag][user]
}

// Summary reports rule, peer and visible pair counts.
func (c *Compiled) Summary() Summary { return c.summary }

// Peers returns the peers the policy was compiled against.
func (c *Compiled) Peers() []Peer { return c.peers }
