package wg

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// exitTable is the policy routing table holding the exit node's
// default route; the rule sending unmarked packets there uses the same
// number as the fwmark.
const (
	exitTable        = DefaultFwMark
	exitRulePriority = 5170
)

func addRoute(name string, p netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("wg: find %s: %w", name, err)
	}
	dst := prefixToIPNet(p)
	if err := netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: &dst, Scope: netlink.SCOPE_LINK, Protocol: unix.RTPROT_STATIC}); err != nil {
		return fmt.Errorf("wg: add route %s via %s: %w", p, name, err)
	}
	return nil
}

func delRoute(name string, p netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil // the interface is gone and its routes with it
	}
	dst := prefixToIPNet(p)
	if err := netlink.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: &dst, Scope: netlink.SCOPE_LINK}); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("wg: remove route %s via %s: %w", p, name, err)
	}
	return nil
}

// setExitRoute installs or removes the wg-quick style default route: a
// table with only "default dev <name>", a rule sending every packet
// not carrying the fwmark to that table, and a rule that lets more
// specific routes of the main table win first (suppress_prefixlength
// 0), so LAN and the WireGuard endpoint itself stay reachable.
func setExitRoute(name string, on bool) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if !on {
			return nil
		}
		return fmt.Errorf("wg: find %s: %w", name, err)
	}
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: &prefixToIPNetVar, Table: exitTable, Scope: netlink.SCOPE_LINK}
	markRule := netlink.NewRule()
	markRule.Priority, markRule.Table, markRule.Mark, markRule.Invert, markRule.Family = exitRulePriority+1, exitTable, DefaultFwMark, true, unix.AF_INET
	mainRule := netlink.NewRule()
	mainRule.Priority, mainRule.Table, mainRule.SuppressPrefixlen, mainRule.Family = exitRulePriority, unix.RT_TABLE_MAIN, 0, unix.AF_INET
	if !on {
		var errs []error
		for _, r := range []*netlink.Rule{markRule, mainRule} {
			if err := netlink.RuleDel(r); err != nil && !errors.Is(err, unix.ENOENT) {
				errs = append(errs, err)
			}
		}
		if err := netlink.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, err)
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("wg: remove exit route via %s: %w", name, err)
		}
		return nil
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("wg: add exit route via %s: %w", name, err)
	}
	for _, r := range []*netlink.Rule{mainRule, markRule} {
		if err := netlink.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
			_ = setExitRoute(name, false)
			return fmt.Errorf("wg: add routing rule for the exit route: %w", err)
		}
	}
	return nil
}

// prefixToIPNetVar is 0.0.0.0/0 as netlink wants it.
var prefixToIPNetVar = prefixToIPNet(ExitRoute)

// EnableIPForward turns on IPv4 forwarding for a subnet router or exit
// node and returns a function restoring the previous value when this
// call changed it (spec 013).
func EnableIPForward() (undo func() error, err error) {
	const path = "/proc/sys/net/ipv4/ip_forward"
	cur, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wg: read %s: %w", path, err)
	}
	if strings.TrimSpace(string(cur)) == "1" {
		return func() error { return nil }, nil
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o600); err != nil { // mode is ignored on procfs
		return nil, fmt.Errorf("wg: enable ip_forward: %w", err)
	}
	return func() error {
		if err := os.WriteFile(path, []byte("0\n"), 0o600); err != nil {
			return fmt.Errorf("wg: restore ip_forward: %w", err)
		}
		return nil
	}, nil
}
