package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/sira-labs/thawr/internal/dns"
)

// DNS modes for DNSOptions.Mode and the --dns flag.
const (
	// DNSOn serves the zone and registers the resolver with the OS.
	DNSOn = "on"
	// DNSServe serves the zone and leaves the OS resolver alone.
	DNSServe = "serve"
	// DNSOff serves nothing.
	DNSOff = "off"
)

// HubName is the zone name of the server's hub address.
const HubName = "hub"

// DNS states in the status document.
const (
	DNSServing = "serving"
	DNSError   = "error"
)

// DNSOptions configure the client's resolver for <name>.thawr. Zero
// values select the production defaults.
type DNSOptions struct {
	// Mode is DNSOn (default), DNSServe or DNSOff.
	Mode string
	// Port defaults to 53.
	Port int
	// Registrar defaults to the platform's; tests inject a fake.
	Registrar dns.Registrar
	// Listen defaults to dns.Listen.
	Listen func(ctx context.Context, addr netip.AddrPort) (net.PacketConn, net.Listener, error)
	// OpTimeout bounds each registrar call (10 s), so a hanging
	// resolvectl or PowerShell never blocks registration or cleanup.
	OpTimeout time.Duration
}

// defaultDNSOpTimeout bounds one registrar call.
const defaultDNSOpTimeout = 10 * time.Second

func (o DNSOptions) withDefaults() DNSOptions {
	if o.Mode == "" {
		o.Mode = DNSOn
	}
	if o.Port == 0 {
		o.Port = 53
	}
	if o.OpTimeout == 0 {
		o.OpTimeout = defaultDNSOpTimeout
	}
	if o.Listen == nil {
		o.Listen = dns.Listen
	}
	return o
}

// ValidDNSMode reports whether m is one of the DNS modes.
func ValidDNSMode(m string) bool {
	switch m {
	case DNSOn, DNSServe, DNSOff, "":
		return true
	}
	return false
}

// DNSStatus reports the client resolver in the status document.
type DNSStatus struct {
	// Listen is the resolver's ip:port.
	Listen string `json:"listen"`
	// State is serving or error.
	State string `json:"state"`
	// Method is how the OS was told about the zone: resolved, hosts,
	// resolver-file, nrpt, or none when not registered.
	Method string `json:"method"`
	// Names counts the names currently served.
	Names int    `json:"names"`
	Error string `json:"error"`
}

// dnsState is the daemon's resolver bookkeeping, guarded by Daemon.mu.
type dnsState struct {
	listen     string
	serving    bool
	err        string
	method     string
	registered bool
}

// netmapSource answers zone lookups from the daemon's current netmap.
// Every peer in the netmap is visible to this device by construction,
// and the resolver answers only this host (dnsServerOptions), so the
// asking address needs no further check.
type netmapSource struct{ d *Daemon }

func (s netmapSource) Lookup(_ context.Context, _ netip.Addr, name string) (netip.Addr, bool) {
	for _, e := range s.d.dnsEntries() {
		if e.Name == name {
			return e.Addr, true
		}
	}
	return netip.Addr{}, false
}

func (s netmapSource) Reverse(_ context.Context, _ netip.Addr, addr netip.Addr) (string, bool) {
	for _, e := range s.d.dnsEntries() {
		if e.Addr == addr {
			return e.Name, true
		}
	}
	return "", false
}

// dnsEntries lists self, the hub and every netmap peer, sorted by name.
func (d *Daemon) dnsEntries() []dns.Entry {
	d.mu.Lock()
	nm := d.netmap
	d.mu.Unlock()
	out := []dns.Entry{{Name: strings.ToLower(d.state.Name), Addr: d.selfIP}, {Name: HubName, Addr: d.overlay.Addr().Next()}}
	if nm != nil {
		for _, p := range nm.Peers {
			ip, err := netip.ParseAddr(p.IPv4)
			if err != nil || p.Name == "" {
				continue
			}
			out = append(out, dns.Entry{Name: strings.ToLower(p.Name), Addr: ip})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// startDNS binds the resolver on the overlay address once the interface
// carries it. A bind failure is reported in status, never fatal: names
// are a convenience, the tunnel is not.
func (d *Daemon) startDNS(ctx context.Context) {
	o := d.opts.DNS
	if o.Mode == DNSOff {
		return
	}
	addr := netip.AddrPortFrom(d.selfIP, uint16(o.Port)) //nolint:gosec // ports are validated on the flag
	udp, tcp, err := o.Listen(ctx, addr)
	d.mu.Lock()
	d.dns.listen = addr.String()
	if err != nil {
		d.dns.err = err.Error()
		d.mu.Unlock()
		d.log.Warn("dns: resolver not started", "listen", addr.String(), "err", err)
		return
	}
	d.dns.serving = true
	d.mu.Unlock()
	srv := dns.NewServer(d.dnsServerOptions())
	go func() {
		if err := srv.Serve(ctx, udp, tcp); err != nil {
			d.mu.Lock()
			d.dns.serving = false
			d.dns.err = err.Error()
			d.mu.Unlock()
			d.log.Error("dns: resolver stopped", "err", err)
			// The OS must not keep routing .thawr to a dead listener.
			d.unregisterDNS(ctx)
		}
	}()
	d.log.Info("dns: serving zone", "zone", dns.Zone, "listen", addr.String())
	// A netmap restored from the cache was applied before the resolver
	// existed; register now that there is something to route to.
	d.registerDNS(ctx)
}

// dnsServerOptions restricts the client resolver to the local host: the
// overlay address it listens on and loopback. Another peer that the
// policy lets reach port 53 gets no answer, so this device's netmap
// (which peers it may see) is never disclosed through names.
func (d *Daemon) dnsServerOptions() dns.Options {
	return dns.Options{Source: netmapSource{d}, Allow: netip.PrefixFrom(d.selfIP, d.selfIP.BitLen()), Reverse: d.overlay, Logger: d.log}
}

// registerDNS routes the zone to the resolver once it serves and a
// netmap has been applied, after clearing what a crashed instance may
// have left, and hands the current entries to the registrar on every
// netmap. Nothing is registered while the resolver is not bound (the
// OS would route .thawr into a void); a failed registration is retried
// with the next netmap. regMu serialises registration, update and
// removal (apply runs from the sync loop and from a key rotation), and
// every registrar call is bounded by OpTimeout so a hanging tool never
// holds the lock for long.
func (d *Daemon) registerDNS(ctx context.Context) {
	o := d.opts.DNS
	if o.Mode != DNSOn || o.Registrar == nil {
		return
	}
	d.dnsRegMu.Lock()
	defer d.dnsRegMu.Unlock()
	d.mu.Lock()
	serving, registered := d.dns.serving, d.dns.registered
	d.mu.Unlock()
	if !serving {
		return
	}
	if !registered {
		if err := d.registrarCall(ctx, func(c context.Context) error { return o.Registrar.Unregister(c, d.iface()) }); err != nil {
			d.log.Debug("dns: clearing previous registration", "err", err)
		}
		var method string
		err := d.registrarCall(ctx, func(c context.Context) (err error) {
			method, err = o.Registrar.Register(c, d.iface(), d.selfIP)
			return err
		})
		d.mu.Lock()
		switch {
		case err == nil:
			d.dns.registered, d.dns.method, d.dns.err = true, method, ""
		case errors.Is(err, dns.ErrUnsupported):
			// Nothing to retry: the platform has no method.
			d.dns.registered, d.dns.method = true, dns.MethodNone
		default:
			d.dns.method, d.dns.err = dns.MethodNone, err.Error()
		}
		d.mu.Unlock()
		switch {
		case errors.Is(err, dns.ErrUnsupported):
			d.log.Warn("dns: no resolver registration on this platform; point your resolver at the listen address for the zone", "zone", dns.Zone, "listen", d.selfIP)
			return
		case err != nil:
			d.log.Warn("dns: resolver registration failed; retrying with the next netmap", "method", method, "err", err)
			return
		default:
			d.log.Info("dns: zone registered", "zone", dns.Zone, "method", method)
		}
	}
	entries := d.dnsEntries()
	if err := d.registrarCall(ctx, func(c context.Context) error { return o.Registrar.Update(c, entries) }); err != nil {
		d.log.Warn("dns: update names", "err", err)
	}
}

// unregisterDNS undoes registerDNS: on shutdown, and when the resolver
// stops while the daemon keeps running, so the OS never routes .thawr
// to a dead listener. It waits for the lock first (the holder is bounded
// by OpTimeout) and only then starts its own budget, detached from
// parent so a cancelled Run still cleans up. The flag is cleared only
// after the registrar succeeded, so a later call retries a failure.
func (d *Daemon) unregisterDNS(parent context.Context) {
	o := d.opts.DNS
	if o.Registrar == nil {
		return
	}
	d.dnsRegMu.Lock()
	defer d.dnsRegMu.Unlock()
	d.mu.Lock()
	registered := d.dns.registered
	d.mu.Unlock()
	if !registered {
		return
	}
	if err := d.registrarCall(context.WithoutCancel(parent), func(c context.Context) error { return o.Registrar.Unregister(c, d.iface()) }); err != nil {
		d.log.Warn("dns: unregister", "err", err)
		return
	}
	d.mu.Lock()
	d.dns.registered = false
	d.dns.method = dns.MethodNone
	d.mu.Unlock()
}

// registrarCall runs one registrar operation under OpTimeout.
func (d *Daemon) registrarCall(ctx context.Context, op func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, d.opts.DNS.OpTimeout)
	defer cancel()
	return op(ctx)
}

// iface is the interface name the device reports, or the configured one
// before the device exists.
func (d *Daemon) iface() string {
	d.mu.Lock()
	dev := d.dev
	d.mu.Unlock()
	if dev != nil {
		return dev.Name()
	}
	return d.opts.Interface
}

// dnsStatus renders the resolver state for the status document; nil
// when the resolver is off.
func (d *Daemon) dnsStatus() *DNSStatus {
	if d.opts.DNS.Mode == DNSOff {
		return nil
	}
	d.mu.Lock()
	s := d.dns
	d.mu.Unlock()
	st := &DNSStatus{Listen: s.listen, State: DNSServing, Method: s.method, Error: s.err, Names: len(d.dnsEntries())}
	if st.Method == "" {
		st.Method = dns.MethodNone
	}
	if !s.serving {
		st.State = DNSError
		if st.Error == "" {
			st.Error = "resolver not started"
		}
	}
	return st
}

// stripZone removes a trailing ".thawr" (and a final dot) from a peer
// name typed by a user.
func stripZone(name string) string {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	return strings.TrimSuffix(n, "."+dns.Zone)
}

// validatePort rejects a DNS port outside 1-65535.
func validatePort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("client: dns port %d out of range", p)
	}
	return nil
}
