package wg

import (
	"fmt"
	"net/netip"
)

func addRoute(name string, p netip.Prefix) error {
	if out, err := netsh(routeArgs("add", name, p)...); err != nil {
		return fmt.Errorf("wg: netsh add route %s via %s: %w: %s", p, name, err, out)
	}
	return nil
}

func delRoute(name string, p netip.Prefix) error {
	if out, err := netsh(routeArgs("delete", name, p)...); err != nil {
		return fmt.Errorf("wg: netsh delete route %s via %s: %w: %s", p, name, err, out)
	}
	return nil
}

// routeArgs are the netsh arguments adding or deleting the route p over
// the interface, in p's family.
func routeArgs(op, name string, p netip.Prefix) []string {
	family := "ipv4"
	if p.Addr().Is6() {
		family = "ipv6"
	}
	args := []string{"interface", family, op, "route", p.Masked().String(), "interface=" + name}
	if op == "add" {
		args = append(args, "metric=1")
	}
	return append(args, "store=active")
}

// setExitRoute is not supported on Windows in this release: without a
// fwmark the tunnel's own packets would enter the tunnel (spec 013).
func setExitRoute(string, netip.Prefix, bool) error {
	return ErrExitNodeUnsupported
}

// EnableIPForward reports that routers need Linux in this release.
func EnableIPForward() (func() error, error) {
	return nil, ErrRouterUnsupported
}
