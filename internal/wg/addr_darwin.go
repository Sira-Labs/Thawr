package wg

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
)

func platformSupported() error { return nil }

// IPv6Available reports whether the host runs IPv6; macOS always does.
func IPv6Available() bool { return true }

// setAddresses configures a utun interface the way wg-quick does on
// macOS: a point-to-point alias per address and a route for its prefix.
func setAddresses(name string, want []netip.Prefix, mtu int) error {
	for _, p := range want {
		for _, args := range addressCommands(name, p) {
			if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
				return fmt.Errorf("wg: %s %s on %s: %w: %s", args[0], p, name, err, out)
			}
		}
	}
	if mtu > 0 {
		if out, err := exec.Command("ifconfig", name, "mtu", strconv.Itoa(mtu)).CombinedOutput(); err != nil {
			return fmt.Errorf("wg: ifconfig %s mtu: %w: %s", name, err, out)
		}
	}
	if out, err := exec.Command("ifconfig", name, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("wg: ifconfig %s up: %w: %s", name, err, out)
	}
	return nil
}

// addressCommands are the ifconfig and route invocations that give the
// interface address p and route p's prefix through it.
func addressCommands(name string, p netip.Prefix) [][]string {
	addr := p.Addr().String()
	ifconfig := []string{"ifconfig", name, "inet", addr, addr, "netmask", maskString(p.Bits()), "alias"}
	if p.Addr().Is6() {
		ifconfig = []string{"ifconfig", name, "inet6", addr, "prefixlen", strconv.Itoa(p.Bits()), "alias"}
	}
	return [][]string{ifconfig, routeCommand("add", name, p)}
}

// routeCommand is `route -q -n <op> -inet|-inet6 <prefix> -interface <name>`.
func routeCommand(op, name string, p netip.Prefix) []string {
	family := "-inet"
	if p.Addr().Is6() {
		family = "-inet6"
	}
	return []string{"route", "-q", "-n", op, family, p.Masked().String(), "-interface", name}
}

// maskString is the dotted IPv4 netmask of a prefix length; IPv6
// prefixes never reach it.
func maskString(bits int) string {
	m := uint32(0xffffffff) << (32 - min(max(bits, 0), 32))
	return fmt.Sprintf("%d.%d.%d.%d", byte(m>>24), byte(m>>16), byte(m>>8), byte(m))
}
