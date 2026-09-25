package client

import (
	"context"
	"net/netip"
	"time"

	thawrv1 "github.com/sira-labs/thawr/internal/api/proto/thawr/v1"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/stun"
	"github.com/sira-labs/thawr/internal/wg"
)

// endpointReport is one ReportEndpoints payload.
type endpointReport struct {
	Endpoints  []control.Endpoint
	Symmetric  bool
	ListenPort int
}

func (r endpointReport) equal(o endpointReport) bool {
	if r.Symmetric != o.Symmetric || r.ListenPort != o.ListenPort || len(r.Endpoints) != len(o.Endpoints) {
		return false
	}
	for i := range r.Endpoints {
		if r.Endpoints[i] != o.Endpoints[i] {
			return false
		}
	}
	return true
}

// shouldSend implements "only on change or every interval".
func shouldSend(prev, cur endpointReport, lastSent, now time.Time, interval time.Duration) bool {
	return lastSent.IsZero() || !cur.equal(prev) || now.Sub(lastSent) >= interval
}

// STUNFunc discovers the reflexive address. shared reports whether the
// transport was the WireGuard socket itself (so the mapped port is the
// WireGuard port) or a separate one.
type STUNFunc func(ctx context.Context, dev wg.Device, servers []netip.AddrPort, timeout time.Duration) (res stun.Result, shared bool, err error)

// discoverSTUN is the default STUNFunc: through the device's socket
// when it can (userspace WireGuard), else from an ephemeral socket.
func discoverSTUN(ctx context.Context, dev wg.Device, servers []netip.AddrPort, timeout time.Duration) (stun.Result, bool, error) {
	if capable, ok := dev.(wg.STUNCapable); ok {
		res, err := stun.Discover(ctx, capable.STUNTransport(), servers, timeout)
		return res, true, err
	}
	tr, err := stun.NewSocketTransport(ctx, 0)
	if err != nil {
		return stun.Result{}, false, err
	}
	defer func() { _ = tr.Close() }()
	res, err := stun.Discover(ctx, tr, servers, timeout)
	return res, false, err
}

// stunServers resolves the STUN addresses of the last netmap.
func (d *Daemon) stunServers() []netip.AddrPort {
	d.mu.Lock()
	nm := d.netmap
	d.mu.Unlock()
	if nm == nil {
		return nil
	}
	var out []netip.AddrPort
	for _, s := range nm.STUN {
		ap, err := resolveEndpoint(s)
		if err != nil {
			d.log.Debug("stun server unresolvable", "addr", s, "err", err)
			continue
		}
		out = append(out, ap)
	}
	return out
}

// reflexiveRound runs STUN and returns the reflexive candidates and the
// symmetric verdict; on failure it returns none, which is what a client
// without NAT information reports.
func (d *Daemon) reflexiveRound(ctx context.Context) ([]control.Endpoint, bool) {
	servers := d.stunServers()
	if len(servers) == 0 {
		return nil, false
	}
	d.mu.Lock()
	dev := d.dev
	d.mu.Unlock()
	res, shared, err := d.opts.STUN(ctx, dev, servers, d.opts.STUNTimeout)
	if err != nil {
		if ctx.Err() == nil {
			d.log.Debug("stun discovery failed", "err", err)
		}
		return nil, false
	}
	d.log.Debug("stun discovery", "mapped", res.Mapped, "symmetric", res.Symmetric, "shared_socket", shared)
	var out []control.Endpoint
	seen := map[netip.AddrPort]bool{}
	for _, m := range res.Mapped {
		ap := m
		if !shared {
			// A separate socket only tells us the public IP; assume the
			// NAT preserves ports for the WireGuard socket. The server
			// adds the exact mapping it observes on the hub.
			ap = netip.AddrPortFrom(m.Addr(), uint16(d.state.ListenPort)) //nolint:gosec // port is 1-65535
		}
		// The server rejects unroutable candidates; a loopback mapping
		// only happens when the STUN server is on this host.
		if a := ap.Addr(); seen[ap] || a.IsLoopback() || a.IsUnspecified() {
			continue
		}
		seen[ap] = true
		out = append(out, control.Endpoint{Addr: ap, Kind: control.EndpointReflexive})
	}
	return out, res.Symmetric
}

// reportLoop discovers endpoints and reports them while the stream
// lives: local addresses are polled every LocalPoll, STUN runs when
// they change or every EndpointInterval, and a report is sent when the
// candidate set changed or EndpointInterval passed.
func (d *Daemon) reportLoop(ctx context.Context, client thawrv1.ControlClient) {
	var (
		last      endpointReport
		lastSent  time.Time
		lastLocal []netip.AddrPort
		lastSTUN  time.Time
		reflexive []control.Endpoint
		symmetric bool
	)
	poll := time.NewTicker(d.opts.LocalPoll)
	defer poll.Stop()
	for {
		now := d.opts.Now()
		local := d.localCandidates()
		if !sameAddrPorts(local, lastLocal) || lastSTUN.IsZero() || now.Sub(lastSTUN) >= d.opts.EndpointInterval {
			reflexive, symmetric = d.reflexiveRound(ctx)
			lastSTUN = now
			lastLocal = local
		}
		rep := endpointReport{ListenPort: d.state.ListenPort, Symmetric: symmetric}
		for _, ap := range local {
			rep.Endpoints = append(rep.Endpoints, control.Endpoint{Addr: ap, Kind: control.EndpointLocal})
		}
		rep.Endpoints = append(rep.Endpoints, reflexive...)
		d.setSelf(local, symmetric, rep.Endpoints)
		if shouldSend(last, rep, lastSent, now, d.opts.EndpointInterval) {
			req := &thawrv1.EndpointReport{ListenPort: uint32(d.state.ListenPort), Symmetric: symmetric} //nolint:gosec // port is 1-65535
			for _, e := range rep.Endpoints {
				req.Endpoints = append(req.Endpoints, &thawrv1.Endpoint{Addr: e.Addr.String(), Kind: thawrv1.EndpointKind(e.Kind)}) //nolint:gosec // kinds 1-3 map 1:1 onto the proto enum
			}
			if _, err := client.ReportEndpoints(ctx, req); err != nil {
				if ctx.Err() != nil {
					return
				}
				d.log.Warn("report endpoints", "err", err)
			} else {
				last, lastSent = rep, now
				d.log.Debug("endpoints reported", "count", len(rep.Endpoints), "symmetric", symmetric)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
		}
	}
}

// localCandidates lists local addresses outside the overlay (another
// Thawr interface on this host is never a way to reach a peer).
func (d *Daemon) localCandidates() []netip.AddrPort {
	var out []netip.AddrPort
	for _, ap := range d.opts.Endpoints(d.state.ListenPort, d.opts.Interface) {
		if d.overlay.Contains(ap.Addr()) {
			continue
		}
		out = append(out, ap)
	}
	return out
}

// setSelf records our own addresses for candidate ordering and status
// and re-ranks every peer's candidates when they changed.
func (d *Daemon) setSelf(local []netip.AddrPort, symmetric bool, all []control.Endpoint) {
	addrs := make([]netip.Addr, 0, len(local))
	for _, ap := range local {
		addrs = append(addrs, ap.Addr())
	}
	d.pmu.Lock()
	changed := d.selfSymmetric != symmetric || !sameAddrs(d.selfAddrs, addrs)
	d.selfAddrs, d.selfSymmetric = addrs, symmetric
	d.selfEndpoints = append(d.selfEndpoints[:0:0], all...)
	if changed {
		d.rankLocked()
	}
	d.pmu.Unlock()
}

func sameAddrPorts(a, b []netip.AddrPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
