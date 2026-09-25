package control

import (
	"net/netip"

	"github.com/sira-labs/thawr/internal/control/policy"
	"github.com/sira-labs/thawr/internal/store"
)

// PolicyVisibility answers visibility and filter questions from the
// compiled policy. Load returns the current compilation (the server
// recompiles when the policy or the registry changes); a nil result
// means nothing is visible.
type PolicyVisibility struct {
	Load func() *policy.Compiled
}

// Visible implements Visibility.
func (v PolicyVisibility) Visible(a, b store.Peer) bool {
	c := v.Load()
	return c != nil && c.Visible(a.ID, b.ID)
}

// FilterFor implements Visibility.
func (v PolicyVisibility) FilterFor(dst store.Peer) []FilterRule {
	c := v.Load()
	if c == nil {
		return nil
	}
	return filterRules(c.FilterFor(dst.ID))
}

// Routing implements Visibility.
func (v PolicyVisibility) Routing(self store.Peer) Routing {
	c := v.Load()
	if c == nil {
		return Routing{}
	}
	var r Routing
	for _, rt := range c.RoutesFor(self.ID) {
		r.Routes = append(r.Routes, Route{Prefix: rt.Prefix, Via: rt.Via})
	}
	r.ExitNodes = c.ExitNodesFor(self.ID)
	for _, f := range c.ForwardFor(self.ID) {
		r.Forward = append(r.Forward, ForwardRule{SrcIPv4: f.Src, Dst: f.Dst, Proto: f.Proto, PortLo: f.Lo, PortHi: f.Hi})
	}
	return r
}

// Snapshot implements Snapshotter: the returned view is bound to the
// compilation current now and never loads again.
func (v PolicyVisibility) Snapshot() Visibility {
	c := v.Load()
	return PolicyVisibility{Load: func() *policy.Compiled { return c }}
}

// filterRules converts compiled rules to netmap rules.
func filterRules(rules []policy.FilterRule) []FilterRule {
	out := make([]FilterRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, FilterRule{SrcIPv4: r.Src, Proto: r.Proto, PortLo: r.Lo, PortHi: r.Hi})
	}
	return out
}

// PolicyPeers converts registered peers into what the compiler needs;
// names resolves owner IDs to user names, routes holds the approved
// prefixes per peer id (spec 013).
func PolicyPeers(peers []store.Peer, names map[string]string, routes map[string][]netip.Prefix) []policy.Peer {
	out := make([]policy.Peer, 0, len(peers))
	for _, p := range peers {
		pp := policy.Peer{ID: p.ID, Name: p.Name, Owner: names[p.OwnerID], Tags: p.Tags, Routes: routes[p.ID]}
		if a, err := netip.ParseAddr(p.IPv4); err == nil {
			pp.IPv4 = a
		}
		out = append(out, pp)
	}
	return out
}
