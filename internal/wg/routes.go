package wg

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// ExitRoute is the prefix that selects an exit node: the default route.
var ExitRoute = netip.MustParsePrefix("0.0.0.0/0")

// DefaultFwMark marks the tunnel's own packets while an exit node is in
// use; the policy routing table of the exit route uses the same number.
const DefaultFwMark = 0x7a77

// routeTable tracks the routes an adapter installed so it changes only
// what it added and removes everything on close.
type routeTable struct {
	mu        sync.Mutex
	installed map[netip.Prefix]bool
	exit      bool
}

// set makes the installed routes equal to want on interface name.
func (r *routeTable) set(name string, want []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.installed == nil {
		r.installed = map[netip.Prefix]bool{}
	}
	wanted := make(map[netip.Prefix]bool, len(want))
	wantExit := false
	for _, p := range want {
		if !p.Addr().Is4() {
			return fmt.Errorf("wg: route %s: only IPv4 prefixes are supported", p)
		}
		if p == ExitRoute {
			wantExit = true
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
	if wantExit != r.exit {
		if err := setExitRoute(name, wantExit); err != nil {
			errs = append(errs, err)
		} else {
			r.exit = wantExit
		}
	}
	return errors.Join(errs...)
}

// clear removes every installed route.
func (r *routeTable) clear(name string) error {
	return r.set(name, nil)
}
