package path

import (
	"net/netip"
	"sort"

	"github.com/sira-labs/thawr/internal/control"
)

// Order ranks a peer's candidates: local addresses sharing a /24 with
// one of ours, other local addresses, reflexive addresses, then stable
// ones. Ties are broken by the address string so both sides agree.
// When both peers are behind endpoint-dependent (symmetric) NAT the
// reflexive addresses cannot work and are skipped.
func Order(ours []netip.Addr, theirs []control.Endpoint, selfSymmetric, peerSymmetric bool) []netip.AddrPort {
	type ranked struct {
		addr  netip.AddrPort
		class int
	}
	seen := map[netip.AddrPort]bool{}
	var list []ranked
	for _, e := range theirs {
		if !e.Addr.IsValid() || seen[e.Addr] {
			continue
		}
		var class int
		switch e.Kind {
		case control.EndpointLocal:
			class = 1
			if sameLAN(ours, e.Addr.Addr()) {
				class = 0
			}
		case control.EndpointReflexive:
			if selfSymmetric && peerSymmetric {
				continue
			}
			class = 2
		case control.EndpointStable:
			class = 3
		default:
			continue
		}
		seen[e.Addr] = true
		list = append(list, ranked{addr: e.Addr, class: class})
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].class != list[j].class {
			return list[i].class < list[j].class
		}
		return list[i].addr.String() < list[j].addr.String()
	})
	out := make([]netip.AddrPort, 0, len(list))
	for _, r := range list {
		out = append(out, r.addr)
	}
	return out
}

// sameLAN reports whether addr shares a /24 with one of ours.
func sameLAN(ours []netip.Addr, addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	want := netip.PrefixFrom(addr, 24).Masked()
	for _, o := range ours {
		if o.Is4() && netip.PrefixFrom(o, 24).Masked() == want {
			return true
		}
	}
	return false
}
