package wg

import (
	"fmt"
	"net/netip"
	"os/exec"
)

func addRoute(name string, p netip.Prefix) error {
	args := routeCommand("add", name, p)
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("wg: route add %s via %s: %w: %s", p, name, err, out)
	}
	return nil
}

func delRoute(name string, p netip.Prefix) error {
	args := routeCommand("delete", name, p)
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("wg: route delete %s via %s: %w: %s", p, name, err, out)
	}
	return nil
}

// setExitRoute is not supported on macOS in this release: without a
// fwmark the tunnel's own packets would enter the tunnel (spec 013).
func setExitRoute(string, netip.Prefix, bool) error {
	return ErrExitNodeUnsupported
}

// EnableIPForward reports that routers need Linux in this release.
func EnableIPForward() (func() error, error) {
	return nil, ErrRouterUnsupported
}
