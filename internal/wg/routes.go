package wg

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// ExitRoute is the prefix that selects an exit node: the default route.
var ExitRoute = netip.MustParsePrefix("0.0.0.0/0")

// ExitRoute6 is the IPv6 default route, carried through an exit node
// that handles IPv6 (spec 015).
var ExitRoute6 = netip.MustParsePrefix("::/0")

// IsExitRoute reports whether p is the default route of either family.
func IsExitRoute(p netip.Prefix) bool {
	return p == ExitRoute || p == ExitRoute6
}

// DefaultFwMark marks the tunnel's own packets while an exit node is in
// use; the policy routing table of the exit route uses the same number.
const DefaultFwMark = 0x7a77

// routeTable tracks the routes an adapter installed so it changes only
// what it added and removes everything on close.
type routeTable struct {
	mu        sync.Mutex
	installed map[netip.Prefix]bool
	// exit holds the families whose exit route is installed, keyed by
	// the default route itself.
	exit map[netip.Prefix]bool
}

// set makes the installed routes equal to want on interface name.
func (r *routeTable) set(name string, want []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.installed == nil {
		r.installed = map[netip.Prefix]bool{}
		r.exit = map[netip.Prefix]bool{}
	}
	wanted := make(map[netip.Prefix]bool, len(want))
	wantExit := map[netip.Prefix]bool{}
	for _, p := range want {
		if !p.IsValid() || p.Addr().Is4In6() {
			return fmt.Errorf("wg: route %s: not an IPv4 or IPv6 prefix", p)
		}
		if IsExitRoute(p) {
			wantExit[p] = true
			continue
		}
		wanted[p.Masked()] = true
	}
	var errs []error
	for p := range r.installed {
		if wanted[p] {
			continue
		}
		if err := delRoute(name, p); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(r.installed, p)
	}
	for p := range wanted {
		if r.installed[p] {
			continue
		}
		if err := addRoute(name, p); err != nil {
			errs = append(errs, err)
			continue
		}
		r.installed[p] = true
	}
	for _, def := range []netip.Prefix{ExitRoute, ExitRoute6} {
		if wantExit[def] == r.exit[def] {
			continue
		}
		if err := setExitRoute(name, def, wantExit[def]); err != nil {
			errs = append(errs, err)
			continue
		}
		r.exit[def] = wantExit[def]
	}
	return errors.Join(errs...)
}

// clear removes every installed route.
func (r *routeTable) clear(name string) error {
	return r.set(name, nil)
}
