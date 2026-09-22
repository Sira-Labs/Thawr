package wg

import (
	"fmt"
	"net/netip"
)

func addRoute(name string, p netip.Prefix) error {
	if out, err := netsh("interface", "ipv4", "add", "route", p.String(), "interface="+name, "metric=1", "store=active"); err != nil {
		return fmt.Errorf("wg: netsh add route %s via %s: %w: %s", p, name, err, out)
	}
	return nil
}

func delRoute(name string, p netip.Prefix) error {
	if out, err := netsh("interface", "ipv4", "delete", "route", p.String(), "interface="+name, "store=active"); err != nil {
		return fmt.Errorf("wg: netsh delete route %s via %s: %w: %s", p, name, err, out)
	}
	return nil
}

// setExitRoute is not supported on Windows in this release: without a
// fwmark the tunnel's own packets would enter the tunnel (spec 013).
func setExitRoute(string, bool) error {
	return ErrExitNodeUnsupported
}

// EnableIPForward reports that routers need Linux in this release.
func EnableIPForward() (func() error, error) {
	return nil, ErrRouterUnsupported
}
