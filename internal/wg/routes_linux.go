package wg

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
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

// setExitRoute installs or removes the wg-quick style default route
// for def's family (0.0.0.0/0 or ::/0): a table with only "default dev
// <name>", a rule sending every packet not carrying the fwmark to that
// table, and a rule that lets more specific routes of the main table
// win first (suppress_prefixlength 0), so LAN and the WireGuard
// endpoint itself stay reachable.
func setExitRoute(name string, def netip.Prefix, on bool) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if !on {
			return nil
		}
		return fmt.Errorf("wg: find %s: %w", name, err)
	}
	route, rules := exitRouteParts(link.Attrs().Index, def)
	if !on {
		var errs []error
		for _, r := range rules {
			if err := netlink.RuleDel(r); err != nil && !errors.Is(err, unix.ENOENT) {
				errs = append(errs, err)
			}
		}
		if err := netlink.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, err)
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("wg: remove exit route %s via %s: %w", def, name, err)
		}
		return nil
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("wg: add exit route %s via %s: %w", def, name, err)
	}
	for _, r := range rules {
		if err := netlink.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
			_ = setExitRoute(name, def, false)
			return fmt.Errorf("wg: add routing rule for the exit route %s: %w", def, err)
		}
	}
	return nil
}

// exitRouteParts is the default route in the exit table and the two
// policy rules (main table first, then everything unmarked to the exit
// table) for def's family.
func exitRouteParts(linkIndex int, def netip.Prefix) (*netlink.Route, []*netlink.Rule) {
	family := unix.AF_INET
	if def.Addr().Is6() {
		family = unix.AF_INET6
	}
	dst := prefixToIPNet(def)
	route := &netlink.Route{LinkIndex: linkIndex, Dst: &dst, Table: exitTable, Scope: netlink.SCOPE_LINK, Family: family}
	mainRule := netlink.NewRule()
	mainRule.Priority, mainRule.Table, mainRule.SuppressPrefixlen, mainRule.Family = exitRulePriority, unix.RT_TABLE_MAIN, 0, family
	markRule := netlink.NewRule()
	markRule.Priority, markRule.Table, markRule.Mark, markRule.Invert, markRule.Family = exitRulePriority+1, exitTable, DefaultFwMark, true, family
	return route, []*netlink.Rule{mainRule, markRule}
}

// procNet is where Linux exposes the network sysctls.
const procNet = "/proc/sys/net"

// EnableIPForward turns on IPv4 and IPv6 forwarding for a subnet router
// or exit node and returns a function restoring what this call changed
// (specs 013, 015). IPv6 forwarding comes with the accept_ra care of
// EnableIPv6Forward.
func EnableIPForward() (undo func() error, err error) {
	return enableIPForward(procNet)
}

func enableIPForward(root string) (func() error, error) {
	undo4, err := setSysctl(filepath.Join(root, "ipv4", "ip_forward"), "1")
	if err != nil {
		return nil, fmt.Errorf("wg: enable ip_forward: %w", err)
	}
	undo6, err := enableIPv6Forward(root)
	if err != nil {
		if uerr := undo4(); uerr != nil {
			err = errors.Join(err, uerr)
		}
		return nil, err
	}
	return func() error { return errors.Join(undo6(), undo4()) }, nil
}

// EnableIPv6Forward turns on net.ipv6.conf.all.forwarding (Linux has no
// per-interface switch for forwarding IPv6) and returns a function
// restoring what this call changed. Once forwarding is on, Linux
// ignores router advertisements on interfaces whose accept_ra is 1,
// which would take a VPS's own IPv6 default route away; those
// interfaces are moved to accept_ra 2 first (spec 015). A host whose
// kernel has IPv6 disabled is left alone.
func EnableIPv6Forward() (undo func() error, err error) {
	return enableIPv6Forward(procNet)
}

// enableIPv6Forward is EnableIPv6Forward against the sysctl tree under
// root, so tests can use a directory instead of /proc/sys/net.
func enableIPv6Forward(root string) (func() error, error) {
	noop := func() error { return nil }
	conf := filepath.Join(root, "ipv6", "conf")
	all := filepath.Join(conf, "all", "forwarding")
	cur, err := os.ReadFile(all)
	if errors.Is(err, fs.ErrNotExist) {
		return noop, nil
	}
	if err != nil {
		return nil, fmt.Errorf("wg: read %s: %w", all, err)
	}
	if strings.TrimSpace(string(cur)) == "1" {
		return noop, nil
	}
	entries, err := os.ReadDir(conf)
	if err != nil {
		return nil, fmt.Errorf("wg: list %s: %w", conf, err)
	}
	var undos []func() error
	restore := func() error {
		var errs []error
		for i := len(undos) - 1; i >= 0; i-- {
			errs = append(errs, undos[i]())
		}
		return errors.Join(errs...)
	}
	for _, e := range entries {
		// "all" is the switch itself; "default" is moved too, so an
		// interface appearing later keeps its router advertisements.
		if !e.IsDir() || e.Name() == "all" {
			continue
		}
		path := filepath.Join(conf, e.Name(), "accept_ra")
		ra, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue // the interface went away
		}
		if err != nil {
			return nil, errors.Join(fmt.Errorf("wg: read %s: %w", path, err), restore())
		}
		if strings.TrimSpace(string(ra)) != "1" {
			continue
		}
		u, err := setSysctl(path, "2")
		if err != nil {
			return nil, errors.Join(fmt.Errorf("wg: keep router advertisements on %s: %w", e.Name(), err), restore())
		}
		undos = append(undos, u)
	}
	u, err := setSysctl(all, "1")
	if err != nil {
		return nil, errors.Join(fmt.Errorf("wg: enable IPv6 forwarding: %w", err), restore())
	}
	undos = append(undos, u)
	return restore, nil
}

// setSysctl writes value to path unless it already holds it and
// returns a function writing the previous value back.
func setSysctl(path, value string) (undo func() error, err error) {
	cur, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	prev := strings.TrimSpace(string(cur))
	if prev == value {
		return func() error { return nil }, nil
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil { // mode is ignored on procfs
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return func() error {
		if err := os.WriteFile(path, []byte(prev+"\n"), 0o600); err != nil { //nolint:gosec // a sysctl path under /proc/sys/net, written back with the value read from it
			return fmt.Errorf("wg: restore %s: %w", path, err)
		}
		return nil
	}, nil
}
