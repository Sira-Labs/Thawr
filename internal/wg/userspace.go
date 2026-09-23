package wg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/thedatadudech/thawr/internal/stun"
)

// userspaceDevice runs wireguard-go on a TUN interface and configures it
// through the in-process IPC API, so no UAPI socket is needed.
type userspaceDevice struct {
	name   string
	mtu    int
	dev    *device.Device
	bind   *stunBind
	filter *packetFilter
	log    *slog.Logger

	mu     sync.Mutex
	closed bool
	routes routeTable
	nft    routerNAT
	// port is the listen port the device holds; Configure sends
	// listen_port only when it changes.
	port int
}

// SetRoutes installs the routes reached through the interface.
func (u *userspaceDevice) SetRoutes(_ context.Context, prefixes []netip.Prefix) error {
	return u.routes.set(u.name, prefixes)
}

func openUserspace(_ context.Context, opts Options) (Device, error) {
	if err := platformSupported(); err != nil {
		return nil, err
	}
	rawTUN, err := tun.CreateTUN(opts.Name, opts.MTU)
	if err != nil {
		return nil, fmt.Errorf("wg: create tun %q: %w", opts.Name, err)
	}
	filter := newPacketFilter(time.Now)
	tdev := &filteredTUN{Device: rawTUN, filter: filter}
	name, err := tdev.Name()
	if err != nil {
		_ = tdev.Close()
		return nil, fmt.Errorf("wg: tun name: %w", err)
	}
	log := opts.Logger.With("interface", name)
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) { log.Debug(fmt.Sprintf(format, args...)) },
		// wireguard-go reports transient conditions (a peer without an
		// endpoint yet, a failed handshake attempt) through Errorf; they
		// are expected during path setup, so they log as warnings and the
		// no-endpoint case, which recurs every keepalive, as debug.
		Errorf: func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			if strings.Contains(msg, "no known endpoint") {
				log.Debug(msg)
				return
			}
			log.Warn(msg)
		},
	}
	bind := newSTUNBind(conn.NewDefaultBind())
	dev := device.NewDevice(tdev, bind, logger)
	return &userspaceDevice{name: name, mtu: opts.MTU, dev: dev, bind: bind, filter: filter, log: log}, nil
}

// SetFilter installs the receiver-side filter between the device and
// the TUN.
func (u *userspaceDevice) SetFilter(ctx context.Context, set FilterSet) error {
	u.filter.Set(set)
	if set.Interface == "" {
		set.Interface = u.name
	}
	// Forwarding and masquerade happen in the kernel even with a
	// userspace tunnel; the TUN is an ordinary interface to it.
	return u.nft.set(ctx, set)
}

// FilterStats reports the userspace filter counters.
func (u *userspaceDevice) FilterStats() FilterStats { return u.filter.Stats() }

// filteredTUN applies the packet filter: packets written toward the TUN
// (inbound from WireGuard) must pass, packets read from the TUN
// (outbound) record flows so their replies pass.
type filteredTUN struct {
	tun.Device
	filter *packetFilter
}

func (t *filteredTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	for i := range n {
		t.filter.Outbound(bufs[i][offset : offset+sizes[i]])
	}
	return n, err
}

func (t *filteredTUN) Write(bufs [][]byte, offset int) (int, error) {
	kept := make([][]byte, 0, len(bufs))
	for _, b := range bufs {
		if t.filter.Inbound(b[offset:]) {
			kept = append(kept, b)
		}
	}
	if len(kept) == 0 {
		return len(bufs), nil
	}
	if _, err := t.Device.Write(kept, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}

func (u *userspaceDevice) Configure(ctx context.Context, cfg Config) error {
	current, err := u.Stats(ctx)
	if err != nil {
		return err
	}
	want := make(map[Key]bool, len(cfg.Peers))
	for _, p := range cfg.Peers {
		want[p.PublicKey] = true
	}
	var remove []Key
	for _, s := range current {
		if !want[s.PublicKey] {
			remove = append(remove, s.PublicKey)
		}
	}
	if err := u.dev.IpcSet(u.render(cfg, remove)); err != nil {
		return fmt.Errorf("wg: configure %s: %w", u.name, err)
	}
	if err := u.dev.Up(); err != nil {
		return fmt.Errorf("wg: bring up %s: %w", u.name, err)
	}
	u.port = cfg.ListenPort
	if err := setAddresses(u.name, cfg.Addresses, u.mtu); err != nil {
		return err
	}
	return nil
}

// render is renderUAPI without the listen port when the device already
// holds it: wireguard-go closes and reopens its socket on every
// listen_port it receives, the same number included, a gap in which
// packets are lost and another process can take the port.
func (u *userspaceDevice) render(cfg Config, remove []Key) string {
	if cfg.ListenPort == u.port {
		cfg.ListenPort = 0
	}
	return renderUAPI(cfg, remove)
}

func (u *userspaceDevice) SetPeer(_ context.Context, p Peer) error {
	if err := u.dev.IpcSet(renderPeerUAPI(p)); err != nil {
		return fmt.Errorf("wg: set peer %s on %s: %w", Fingerprint(p.PublicKey), u.name, err)
	}
	return nil
}

func (u *userspaceDevice) RemovePeer(_ context.Context, key Key) error {
	if err := u.dev.IpcSet(renderRemoveUAPI(key)); err != nil {
		return fmt.Errorf("wg: remove peer %s on %s: %w", Fingerprint(key), u.name, err)
	}
	return nil
}

// STUNTransport sends and receives STUN through the device's own socket,
// so the reflexive address is that of the WireGuard port.
func (u *userspaceDevice) STUNTransport() stun.Transport { return u.bind.transport() }

func (u *userspaceDevice) Stats(context.Context) ([]PeerStats, error) {
	out, err := u.dev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("wg: stats %s: %w", u.name, err)
	}
	return parseUAPIStats(out)
}

func (u *userspaceDevice) Backend() string { return "userspace" }

func (u *userspaceDevice) Name() string { return u.name }

func (u *userspaceDevice) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	var errs []error
	if err := u.routes.clear(u.name); err != nil {
		errs = append(errs, err)
	}
	if err := u.nft.remove(); err != nil {
		errs = append(errs, err)
	}
	// Closing the device also closes the TUN, which removes the interface.
	u.dev.Close()
	return errors.Join(errs...)
}
