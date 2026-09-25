package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	thawrv1 "github.com/sira-labs/thawr/internal/api/proto/thawr/v1"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/control/path"
	"github.com/sira-labs/thawr/internal/relay"
	"github.com/sira-labs/thawr/internal/wg"
)

// ErrUnknownPeer is returned by Ping for a name not in the netmap.
var ErrUnknownPeer = errors.New("client: unknown peer")

// peerPath is the per-peer probing state.
type peerPath struct {
	id, name  string
	key       wg.Key
	ipv4      netip.Addr
	peer      wg.Peer // allowed IPs and keepalive from the netmap
	cands     []control.Endpoint
	symmetric bool
	machine   *path.Machine
	sink      *sink
	ping      bool
	steps     int
	state     path.State
	endpoint  netip.AddrPort
}

// PathResult is the outcome of a ping.
type PathResult struct {
	Peer     string `json:"peer"`
	State    string `json:"state"`
	Endpoint string `json:"endpoint,omitempty"`
}

// TriggerFunc sends one packet from src to dst through the WireGuard
// interface iface so WireGuard initiates a handshake toward the peer's
// current endpoint.
type TriggerFunc func(ctx context.Context, iface string, src, dst netip.Addr) error

// triggerUDP is the default TriggerFunc: one byte to the discard port,
// bound to the interface where the platform allows it.
func triggerUDP(ctx context.Context, iface string, src, dst netip.Addr) error {
	dialer := net.Dialer{LocalAddr: &net.UDPAddr{IP: src.AsSlice()}, Timeout: time.Second, Control: bindToInterface(iface)}
	c, err := dialer.DialContext(ctx, "udp4", netip.AddrPortFrom(dst, 9).String())
	if err != nil {
		return fmt.Errorf("client: trigger %s: %w", dst, err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte{0}); err != nil {
		return fmt.Errorf("client: trigger %s: %w", dst, err)
	}
	return nil
}

// syncPaths reconciles the per-peer probing state with a netmap: new
// peers get a sink and a machine, removed peers are dropped, candidate
// lists are re-ranked. cfg is the device configuration built from nm.
func (d *Daemon) syncPaths(ctx context.Context, nm NetMap, cfg wg.Config) error {
	byKey := make(map[wg.Key]wg.Peer, len(cfg.Peers))
	for _, p := range cfg.Peers {
		byKey[p.PublicKey] = p
	}
	d.pmu.Lock()
	defer d.pmu.Unlock()
	seen := map[string]bool{}
	var errs []error
	for _, p := range nm.Peers {
		if p.ViaHub {
			continue // routed by the hub, nothing to probe
		}
		key, err := wg.ParseKey(p.PublicKey)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(p.IPv4)
		if err != nil {
			continue
		}
		seen[p.ID] = true
		pp, ok := d.paths[p.ID]
		if !ok {
			s, err := newSink(ctx)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			pp = &peerPath{id: p.ID, machine: path.New(d.opts.Path), sink: s, state: path.Idle}
			d.paths[p.ID] = pp
		} else if pp.key != key {
			// Key rotation: the session is gone, start over.
			pp.machine = path.New(d.opts.Path)
			d.relay.Release(relay.Key(pp.key))
		}
		pp.name, pp.key, pp.ipv4, pp.peer = p.Name, key, ip, byKey[key]
		pp.cands, pp.symmetric = p.Candidates(), p.Symmetric
	}
	for id, pp := range d.paths {
		if !seen[id] {
			pp.sink.close()
			d.relay.Release(relay.Key(pp.key))
			delete(d.paths, id)
		}
	}
	d.rankLocked()
	d.wakePaths()
	return errors.Join(errs...)
}

// rankLocked recomputes every peer's candidate order; pmu held.
func (d *Daemon) rankLocked() {
	for _, pp := range d.paths {
		pp.machine.SetCandidates(path.Order(d.selfAddrs, pp.cands, d.selfSymmetric, pp.symmetric))
	}
}

func (d *Daemon) wakePaths() {
	select {
	case d.pathWake <- struct{}{}:
	default:
	}
}

func (d *Daemon) closeSinks() {
	d.pmu.Lock()
	for id, pp := range d.paths {
		pp.sink.close()
		delete(d.paths, id)
	}
	d.pmu.Unlock()
	d.relay.Close()
}

// pathLoop steps every peer's machine on a timer: fast while a probe is
// in flight, slow otherwise, and immediately when woken.
func (d *Daemon) pathLoop(ctx context.Context) {
	for {
		d.pathTick(ctx)
		tick := d.opts.IdleTick
		if d.anyProbing() {
			tick = d.opts.ProbeTick
		}
		timer := time.NewTimer(tick)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-d.pathWake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (d *Daemon) anyProbing() bool {
	d.pmu.Lock()
	defer d.pmu.Unlock()
	for _, pp := range d.paths {
		if pp.machine.State() == path.Probing {
			return true
		}
	}
	return false
}

// pathTick reads the device once and steps every machine.
func (d *Daemon) pathTick(ctx context.Context) {
	d.mu.Lock()
	dev := d.dev
	d.mu.Unlock()
	if dev == nil {
		return
	}
	stats := map[wg.Key]wg.PeerStats{}
	if list, err := dev.Stats(ctx); err == nil {
		for _, s := range list {
			stats[s.PublicKey] = s
		}
	} else if ctx.Err() == nil {
		d.log.Debug("device stats", "err", err)
	}
	now := d.opts.Now()
	if fd, ok := dev.(wg.Filterable); ok {
		d.drops.Record(now, fd.FilterStats().Drops)
	}
	var report []PathResult
	d.pmu.Lock()
	changed := false
	for _, pp := range d.paths {
		in := path.Input{Now: now, Intent: pp.sink.takeIntent() || pp.ping}
		pp.ping = false
		if s, ok := stats[pp.key]; ok {
			in.Handshake, in.Rx, in.Tx = s.LastHandshake, s.RxBytes, s.TxBytes
			// Loopback endpoints are our own sink or relay proxy, never a
			// real address of the peer.
			if s.Endpoint.IsValid() && !s.Endpoint.Addr().IsLoopback() {
				in.Endpoint = s.Endpoint
			}
		}
		prev := pp.state
		out := pp.machine.Step(in)
		pp.steps++
		switch out.Action {
		case path.ActSink:
			d.setPeerEndpoint(ctx, dev, pp, pp.sink.endpoint(), false)
		case path.ActRelay:
			ep, err := d.relay.Endpoint(ctx, relay.Key(pp.key))
			if err != nil {
				d.log.Warn("relay proxy", "peer", pp.name, "err", err)
				d.setPeerEndpoint(ctx, dev, pp, pp.sink.endpoint(), false)
				break
			}
			d.setPeerEndpoint(ctx, dev, pp, ep, true)
			if err := d.opts.Trigger(ctx, dev.Name(), d.selfIP, pp.ipv4); err != nil && ctx.Err() == nil {
				d.log.Debug("relay trigger", "peer", pp.name, "err", err)
			}
		case path.ActProbe:
			d.setPeerEndpoint(ctx, dev, pp, out.Endpoint, true)
			if err := d.opts.Trigger(ctx, dev.Name(), d.selfIP, pp.ipv4); err != nil && ctx.Err() == nil {
				d.log.Debug("probe trigger", "peer", pp.name, "err", err)
			}
			d.log.Debug("probing", "peer", pp.name, "endpoint", out.Endpoint, "attempt", pp.machine.Probes())
		case path.ActNone:
		}
		if out.Changed {
			pp.state, pp.endpoint = out.State, out.Endpoint
			changed = true
			if prev == path.Relay && out.State != path.Relay && out.State != path.Probing {
				d.relay.Release(relay.Key(pp.key))
			}
			d.log.Info("path", "peer", pp.name, "state", out.State, "endpoint", out.Endpoint)
		}
	}
	if changed {
		for _, pp := range d.paths {
			report = append(report, pp.result())
		}
	}
	d.pmu.Unlock()
	if changed {
		d.reportPaths(ctx, report)
	}
}

func (pp *peerPath) result() PathResult {
	r := PathResult{Peer: pp.name, State: string(pp.state)}
	if pp.endpoint.IsValid() && pp.state != path.Idle && pp.state != path.Unreachable {
		r.Endpoint = pp.endpoint.String()
	}
	return r
}

// viaHub reports whether the current netmap lists name as a peer routed
// through the hub.
func (d *Daemon) viaHub(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.netmap == nil {
		return false
	}
	for _, p := range d.netmap.Peers {
		if p.Name == name && p.ViaHub {
			return true
		}
	}
	return false
}

// setPeerEndpoint points the peer at ep; readd removes it first so
// WireGuard starts a fresh handshake immediately (its retry timer would
// otherwise hold the next initiation for 5 s).
func (d *Daemon) setPeerEndpoint(ctx context.Context, dev wg.Device, pp *peerPath, ep netip.AddrPort, readd bool) {
	d.devMu.Lock()
	defer d.devMu.Unlock()
	if readd {
		if err := dev.RemovePeer(ctx, pp.key); err != nil && ctx.Err() == nil {
			d.log.Warn("remove peer for probe", "peer", pp.name, "err", err)
		}
	}
	peer := pp.peer
	peer.PublicKey, peer.Endpoint = pp.key, ep
	if len(peer.AllowedIPs) == 0 {
		peer.AllowedIPs = []netip.Prefix{netip.PrefixFrom(pp.ipv4, 32)}
	}
	if err := dev.SetPeer(ctx, peer); err != nil && ctx.Err() == nil {
		d.log.Warn("set peer endpoint", "peer", pp.name, "err", err)
	}
}

// reportPaths sends every peer's state to the server when connected.
func (d *Daemon) reportPaths(ctx context.Context, results []PathResult) {
	d.mu.Lock()
	client := d.client
	d.mu.Unlock()
	if client == nil {
		return
	}
	req := &thawrv1.PathReport{}
	d.pmu.Lock()
	byName := map[string]string{}
	for _, pp := range d.paths {
		byName[pp.name] = pp.id
	}
	d.pmu.Unlock()
	for _, r := range results {
		req.Paths = append(req.Paths, &thawrv1.PathState{PeerId: byName[r.Peer], State: r.State, Endpoint: r.Endpoint})
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := client.ReportPath(rctx, req); err != nil && ctx.Err() == nil {
		d.log.Debug("report paths", "err", err)
	}
}

// Ping marks traffic intent toward the named peer, lets the prober run
// and returns the resulting path once it is settled (direct or
// unreachable) or ctx ends. A peer reached through the hub has no path
// of its own and answers "hub" at once.
func (d *Daemon) Ping(ctx context.Context, name string) (PathResult, error) {
	name = stripZone(name)
	d.pmu.Lock()
	var target *peerPath
	for _, pp := range d.paths {
		if pp.name == name {
			target = pp
		}
	}
	if target == nil {
		d.pmu.Unlock()
		if d.viaHub(name) {
			return PathResult{Peer: name, State: PathHub}, nil
		}
		return PathResult{}, fmt.Errorf("%w: %s", ErrUnknownPeer, name)
	}
	target.ping = true
	since := target.steps
	d.pmu.Unlock()
	d.wakePaths()
	for {
		d.pmu.Lock()
		res, settled := target.result(), target.steps > since && target.state != path.Probing
		d.pmu.Unlock()
		if settled {
			return res, nil
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// pathOf returns the state of the path to peerID for status.
func (d *Daemon) pathOf(peerID string) (state path.State, endpoint netip.AddrPort, probes int, ok bool) {
	d.pmu.Lock()
	defer d.pmu.Unlock()
	pp, ok := d.paths[peerID]
	if !ok {
		return "", netip.AddrPort{}, 0, false
	}
	return pp.state, pp.endpoint, pp.machine.Probes(), true
}
