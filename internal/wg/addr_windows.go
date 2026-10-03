package wg

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"time"
)

// Windows support is untested against a real host (see docs/TESTING.md);
// it compiles in CI and follows what wireguard-windows does with netsh.
func platformSupported() error { return nil }

// IPv6Available reports whether the host runs IPv6; Windows always does.
func IPv6Available() bool { return true }

// setAddresses configures the interface through netsh: a static address
// with the prefix's mask and a route for the prefix over the interface.
func setAddresses(name string, want []netip.Prefix, mtu int) error {
	for _, args := range addressCommands(name, want) {
		if out, err := netsh(args...); err != nil {
			return fmt.Errorf("wg: netsh %v on %s: %w: %s", args[1:4], name, err, out)
		}
	}
	if mtu > 0 {
		families := []string{"ipv4"}
		if hasFamily6(want) {
			families = append(families, "ipv6")
		}
		for _, family := range families {
			if out, err := netsh("interface", family, "set", "subinterface", name, "mtu="+strconv.Itoa(mtu), "store=active"); err != nil {
				return fmt.Errorf("wg: netsh set %s mtu on %s: %w: %s", family, name, err, out)
			}
		}
	}
	return nil
}

// addressCommands are the netsh arguments giving the interface the
// addresses in want: the first IPv4 address replaces whatever the
// interface had, later ones and IPv6 addresses are added.
func addressCommands(name string, want []netip.Prefix) [][]string {
	var cmds [][]string
	first4 := true
	for _, p := range want {
		switch {
		case p.Addr().Is6():
			cmds = append(cmds, []string{"interface", "ipv6", "add", "address", "interface=" + name, "address=" + p.String(), "store=active"})
		case first4:
			cmds = append(cmds, []string{"interface", "ipv4", "set", "address", "name=" + name, "static", p.Addr().String(), maskString(p.Bits())})
			first4 = false
		default:
			cmds = append(cmds, []string{"interface", "ipv4", "add", "address", "name=" + name, p.Addr().String(), maskString(p.Bits())})
		}
	}
	return cmds
}

func hasFamily6(ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Addr().Is6() {
			return true
		}
	}
	return false
}

func netsh(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "netsh", args...).CombinedOutput()
}

// maskString is the dotted IPv4 netmask of a prefix length; IPv6
// prefixes never reach it.
func maskString(bits int) string {
	m := uint32(0xffffffff) << (32 - min(max(bits, 0), 32))
	return fmt.Sprintf("%d.%d.%d.%d", byte(m>>24), byte(m>>16), byte(m>>8), byte(m))
}
