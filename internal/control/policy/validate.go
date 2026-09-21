package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

// Registry is what validation needs to know about the world: existing
// user names, peer names and tags, and the overlay prefix that tells a
// peer-selecting CIDR from a subnet route (spec 013).
type Registry struct {
	Users   []string
	Peers   []string
	Tags    []string
	Overlay netip.Prefix
}

// Validate checks the policy against the registry. Unknown users and
// groups are errors; unknown tags and peers are warnings, so a policy
// can be written before the peers enrol. The returned error joins
// every problem, each naming the rule index and field.
func (p *Policy) Validate(reg Registry) (warnings []string, err error) {
	users := set(reg.Users)
	peers := set(reg.Peers)
	tags := set(reg.Tags)
	var errs []error
	for _, name := range sortedKeys(p.Groups) {
		for i, m := range p.Groups[name] {
			sel, perr := ParseSelector(m, false)
			if perr == nil && !users[sel.Name] {
				errs = append(errs, fmt.Errorf("groups.%s[%d]: unknown user %q", name, i, sel.Name))
			}
		}
	}
	check := func(where string, sel Selector) {
		switch sel.Kind {
		case SelUser:
			if !users[sel.Name] {
				errs = append(errs, fmt.Errorf("%s: unknown user %q", where, sel.Name))
			}
		case SelGroup:
			if _, ok := p.Groups[sel.Name]; !ok {
				errs = append(errs, fmt.Errorf("%s: unknown group %q", where, sel.Name))
			}
		case SelTag:
			if !tags["tag:"+sel.Name] {
				warnings = append(warnings, fmt.Sprintf("%s: no peer carries tag:%s yet", where, sel.Name))
			}
		case SelPeer:
			if !peers[sel.Name] {
				warnings = append(warnings, fmt.Sprintf("%s: no peer named %q yet", where, sel.Name))
			}
		case SelCIDR:
			// Inside the overlay it selects peers, outside it is a route;
			// a prefix that contains the overlay is neither.
			if reg.Overlay.IsValid() && sel.Prefix.Overlaps(reg.Overlay) && !reg.Overlay.Contains(sel.Prefix.Addr()) {
				errs = append(errs, fmt.Errorf("%s: %s overlaps the overlay %s", where, sel.Prefix, reg.Overlay))
			}
		case SelAny, SelSelf, SelInternet:
		}
	}
	for _, tag := range sortedKeys(p.TagOwners) {
		for i, o := range p.TagOwners[tag] {
			if sel, perr := ParseSelector(o, false); perr == nil {
				check(fmt.Sprintf("tagOwners.%s[%d]", tag, i), sel)
			}
		}
	}
	for i, r := range p.rules {
		for j, s := range r.src {
			check(fmt.Sprintf("acls[%d].src[%d]", i, j), s)
		}
		for j, d := range r.dst {
			check(fmt.Sprintf("acls[%d].dst[%d]", i, j), d.Host)
		}
	}
	if len(errs) > 0 {
		return warnings, fmt.Errorf("policy: %w", errors.Join(errs...))
	}
	return warnings, nil
}

func set(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[s] = true
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
