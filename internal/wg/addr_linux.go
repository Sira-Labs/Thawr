package wg

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func platformSupported() error { return nil }

// IPv6Available reports whether the kernel runs IPv6; it does not when
// booted with ipv6.disable=1, and then the IPv6 overlay address is left
// out (spec 015).
func IPv6Available() bool {
	_, err := os.Stat(filepath.Join(procNet, "ipv6"))
	return err == nil
}

// setAddresses makes the interface's addresses of both families equal
// to want and brings the link up. IPv6 addresses skip duplicate address
// detection: the overlay address is unique by construction, and DAD
// would hold it back for a second. Link-local addresses the kernel may
// have added are kept.
func setAddresses(name string, want []netip.Prefix, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("wg: find %s: %w", name, err)
	}
	have, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("wg: list addresses on %s: %w", name, err)
	}
	v6 := IPv6Available()
	wanted := make(map[string]netip.Prefix, len(want))
	for _, p := range want {
		if p.Addr().Is6() && !v6 {
			continue
		}
		wanted[p.String()] = p
	}
	if v6 && hasIPv6(wanted) {
		if err := enableInterfaceIPv6(procNet, name); err != nil {
			return err
		}
	}
	for _, a := range have {
		if a.IP.IsLinkLocalUnicast() {
			continue
		}
		key := a.IPNet.String()
		if _, ok := wanted[key]; ok {
			delete(wanted, key)
			continue
		}
		if err := netlink.AddrDel(link, &a); err != nil {
			return fmt.Errorf("wg: remove address %s from %s: %w", key, name, err)
		}
	}
	for key, p := range wanted {
		ipnet := prefixToIPNet(p)
		addr := &netlink.Addr{IPNet: &ipnet}
		if p.Addr().Is6() {
			addr.Flags = unix.IFA_F_NODAD
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("wg: add address %s to %s: %w", key, name, err)
		}
	}
	if mtu > 0 && link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("wg: set mtu on %s: %w", name, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("wg: bring up %s: %w", name, err)
	}
	return nil
}

func prefixToIPNet(p netip.Prefix) net.IPNet {
	addr := p.Addr()
	bits := addr.BitLen()
	return net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(p.Bits(), bits)}
}

func hasIPv6(m map[string]netip.Prefix) bool {
	for _, p := range m {
		if p.Addr().Is6() {
			return true
		}
	}
	return false
}

// enableInterfaceIPv6 clears disable_ipv6 on the interface, which
// net.ipv6.conf.default.disable_ipv6=1 sets on every new interface.
func enableInterfaceIPv6(root, name string) error {
	path := filepath.Join(root, "ipv6", "conf", name, "disable_ipv6")
	if _, err := setSysctl(path, "0"); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("wg: enable IPv6 on %s: %w", name, err)
	}
	return nil
}
