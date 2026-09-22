package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	thawrv1 "github.com/thedatadudech/thawr/internal/api/proto/thawr/v1"
	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/control/path"
	"github.com/thedatadudech/thawr/internal/dns"
	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/relay"
	"github.com/thedatadudech/thawr/internal/wg"
)

// DefaultSocket is the local control socket of the running daemon.
const DefaultSocket = "/var/run/thawr/client.sock"

// DaemonOptions configure Run. Zero values select production defaults.
type DaemonOptions struct {
	StateDir  string
	Socket    string
	Interface string
	// OpenDevice defaults to wg.Open.
	OpenDevice func(ctx context.Context, opts wg.Options) (wg.Device, error)
	Logger     *slog.Logger
	Version    string
	Now        func() time.Time
	// MinBackoff and MaxBackoff bound the reconnect delay (1 s, 60 s).
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// EndpointInterval is the periodic endpoint report (60 s).
	EndpointInterval time.Duration
	// Endpoints overrides local endpoint discovery (tests).
	Endpoints func(port int, ignoreIface string) []netip.AddrPort
	// LocalPoll is how often local addresses are re-read (15 s).
	LocalPoll time.Duration
	// STUN overrides reflexive discovery (tests); STUNTimeout is per
	// attempt (2 s).
	STUN        STUNFunc
	STUNTimeout time.Duration
	// Path tunes the per-peer state machine; ProbeTick and IdleTick are
	// the prober's cadence while probing (250 ms) and otherwise (5 s).
	Path      path.Options
	ProbeTick time.Duration
	IdleTick  time.Duration
	// Trigger overrides the probe packet (tests).
	Trigger TriggerFunc
	// Relay tunes the relay client's timing; server, credentials and
	// port always come from the enrollment state.
	Relay relay.ClientOptions
	// DNS configures the <name>.thawr resolver (spec 010).
	DNS DNSOptions
	// EnableForward turns on kernel forwarding for a router and returns
	// the undo; defaults to wg.EnableIPForward (tests inject a no-op).
	EnableForward func() (func() error, error)
}

func (o DaemonOptions) withDefaults() DaemonOptions {
	if o.StateDir == "" {
		o.StateDir = DefaultDir()
	}
	if o.Socket == "" {
		o.Socket = DefaultSocket
	}
	if o.Interface == "" {
		o.Interface = "thawr0"
	}
	if o.OpenDevice == nil {
		o.OpenDevice = wg.Open
	}
	if o.EnableForward == nil {
		o.EnableForward = wg.EnableIPForward
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Version == "" {
		o.Version = "dev"
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MinBackoff == 0 {
		o.MinBackoff = time.Second
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = 60 * time.Second
	}
	if o.EndpointInterval == 0 {
		o.EndpointInterval = 60 * time.Second
	}
	if o.Endpoints == nil {
		o.Endpoints = LocalEndpoints
	}
	if o.LocalPoll == 0 {
		o.LocalPoll = 15 * time.Second
	}
	if o.STUN == nil {
		o.STUN = discoverSTUN
	}
	if o.STUNTimeout == 0 {
		o.STUNTimeout = 2 * time.Second
	}
	if o.ProbeTick == 0 {
		o.ProbeTick = 250 * time.Millisecond
	}
	if o.IdleTick == 0 {
		o.IdleTick = 5 * time.Second
	}
	if o.Trigger == nil {
		o.Trigger = triggerUDP
	}
	o.Path.Relay = true
	o.DNS = o.DNS.withDefaults()
	if o.DNS.Registrar == nil && o.DNS.Mode == DNSOn {
		o.DNS.Registrar = dns.NewRegistrar(dns.RegistrarOptions{Logger: o.Logger})
	}
	return o
}

// Daemon keeps the WireGuard interface in sync with the server's netmap.
type Daemon struct {
	opts    DaemonOptions
	log     *slog.Logger
	state   State
	overlay netip.Prefix
	selfIP  netip.Addr

	// devMu serialises multi-step device changes (probe re-adds).
	devMu sync.Mutex
	// applyMu serialises apply end to end, so a re-apply of the last
	// received netmap (trust, key rotation) reads it under the same
	// lock and can never overwrite a newer one with a stale snapshot.
	applyMu    sync.Mutex
	filterWarn sync.Once
	// lockWarn reports a refused lock record once until it is adopted;
	// selfUnsignedWarn likewise while this device's record is unsigned.
	lockWarn         sync.Once
	selfUnsignedWarn sync.Once

	// pmu guards the path prober's state.
	pmu           sync.Mutex
	paths         map[string]*peerPath
	selfAddrs     []netip.Addr
	selfSymmetric bool
	selfEndpoints []control.Endpoint
	pathWake      chan struct{}
	relay         *relay.Client

	// drops samples the filter's drop counter for the 5-minute window.
	drops *dropWindow
	// dns is the resolver's state (guarded by mu).
	dns dnsState
	// dnsRegMu serialises resolver registration and removal.
	dnsRegMu sync.Mutex

	mu     sync.Mutex
	key    wg.Key
	dev    wg.Device
	netmap *NetMap
	// offered is the last netmap as received, before held entries were
	// removed; Trust re-applies it. pins and held are what the client
	// accepted and what it currently refuses (spec 011).
	offered *NetMap
	pins    *Pins
	held    []HeldStatus
	// lockKey is this device's lock key (zero without one) and
	// lockRejected why the server's offered lock record was not
	// adopted (spec 012).
	lockKey      lock.PrivateKey
	lockRejected string
	// advertise is what this device offers to route (from state),
	// advertised what the server last reported about it, and exitNode
	// the peer whose exit node this device uses (spec 013).
	advertise  []netip.Prefix
	advertised []AdvertisedRoute
	exitNode   string
	routesWarn sync.Once
	// resyncNow ends the current sync stream so the next one carries
	// fresh SyncRequest fields (a new lock key); resyncWanted tells the
	// loop to reconnect at once instead of backing off.
	resyncNow    context.CancelFunc
	resyncWanted bool
	connected    bool
	lastError    string
	// attempt counts failed connects since the last good one,
	// nextRetryAt is when the next try is due, unreachableSince is when
	// the server was last heard from (zero while connected), and
	// lastMessage is the last stream message of any kind.
	attempt          int
	nextRetryAt      time.Time
	unreachableSince time.Time
	lastMessage      time.Time
	client           thawrv1.ControlClient
	stop             context.CancelFunc
	// mapCh delivers applied netmaps to observers (tests).
	mapCh chan NetMap
}

// NewDaemon loads the enrollment state and key. It fails with
// ErrNotEnrolled when the device has not enrolled.
func NewDaemon(opts DaemonOptions) (*Daemon, error) {
	opts = opts.withDefaults()
	if !ValidDNSMode(opts.DNS.Mode) {
		return nil, fmt.Errorf("client: dns mode %q is not on, serve or off", opts.DNS.Mode)
	}
	if err := validatePort(opts.DNS.Port); err != nil {
		return nil, err
	}
	st, err := LoadState(opts.StateDir)
	if err != nil {
		return nil, err
	}
	key, err := LoadKey(opts.StateDir)
	if err != nil {
		return nil, err
	}
	overlay, err := netip.ParsePrefix(st.OverlayCIDR)
	if err != nil {
		return nil, fmt.Errorf("client: overlay %q in state: %w", st.OverlayCIDR, err)
	}
	if st.ListenPort == 0 {
		st.ListenPort, err = randomPort()
		if err != nil {
			return nil, err
		}
		if err := SaveState(opts.StateDir, st); err != nil {
			return nil, err
		}
	}
	selfIP, err := netip.ParseAddr(st.IPv4)
	if err != nil {
		return nil, fmt.Errorf("client: address %q in state: %w", st.IPv4, err)
	}
	pins, err := LoadPins(opts.StateDir)
	if err != nil {
		return nil, err
	}
	lockKey, err := LoadLockKey(opts.StateDir)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := PinnedTLSConfig(st.Fingerprint)
	if err != nil {
		return nil, err
	}
	log := opts.Logger.With("peer", st.Name)
	ro := opts.Relay
	ro.ServerURL, ro.TLS, ro.NodeSecret, ro.WireGuardPort, ro.Logger = st.Server, tlsCfg, st.NodeSecret, st.ListenPort, log
	if ro.Now == nil {
		ro.Now = opts.Now
	}
	advertise, err := ParseAdvertised(st.AdvertiseRoutes, overlay)
	if err != nil {
		return nil, err
	}
	return &Daemon{opts: opts, log: log, state: st, overlay: overlay.Masked(), selfIP: selfIP, key: key, pins: pins, lockKey: lockKey,
		advertise: advertise, exitNode: st.ExitNode,
		mapCh: make(chan NetMap, 16), paths: map[string]*peerPath{}, pathWake: make(chan struct{}, 1), relay: relay.NewClient(ro),
		drops: newDropWindow(5 * time.Minute)}, nil
}

// ParseAdvertised validates the prefixes a device advertises: canonical
// IPv4 CIDRs outside the overlay, 0.0.0.0/0 for an exit node.
func ParseAdvertised(raw []string, overlay netip.Prefix) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(raw))
	for _, r := range raw {
		p, err := netip.ParsePrefix(strings.TrimSpace(r))
		if err != nil {
			return nil, fmt.Errorf("client: advertised route %q: %w", r, err)
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("client: advertised route %q: only IPv4 prefixes are supported", r)
		}
		if p.Masked() != p {
			return nil, fmt.Errorf("client: advertised route %q is not canonical (use %s)", r, p.Masked())
		}
		if p != wg.ExitRoute && overlay.IsValid() && p.Overlaps(overlay) {
			return nil, fmt.Errorf("client: advertised route %q overlaps the overlay %s", r, overlay)
		}
		out = append(out, p)
	}
	return out, nil
}

// randomPort picks a listen port in the dynamic range.
func randomPort() (int, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("client: random port: %w", err)
	}
	return 49152 + int(binary.BigEndian.Uint16(b[:]))%(65535-49152), nil
}

// Run brings up the interface, restores the cached netmap, serves the
// local API and syncs with the server until ctx ends.
func (d *Daemon) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.mu.Lock()
	d.stop = cancel
	d.mu.Unlock()

	dev, err := d.opts.OpenDevice(ctx, wg.Options{Name: d.opts.Interface, Logger: d.log})
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.dev = dev
	d.mu.Unlock()
	defer func() {
		d.closeSinks()
		if err := dev.Close(); err != nil {
			d.log.Error("close device", "err", err)
		}
	}()
	if len(d.advertise) > 0 {
		// A router forwards for others: the kernel must forward, and the
		// previous setting comes back when the daemon stops.
		undo, err := d.opts.EnableForward()
		if err != nil {
			return fmt.Errorf("client: advertise routes: %w", err)
		}
		defer func() {
			if err := undo(); err != nil {
				d.log.Warn("restore ip_forward", "err", err)
			}
		}()
		d.log.Info("advertising routes", "routes", d.advertise)
	}

	if nm, ok, err := LoadNetMap(d.opts.StateDir); err != nil {
		d.log.Warn("netmap cache unreadable, ignoring", "err", err)
	} else if ok {
		if err := d.apply(ctx, nm, false); err != nil {
			d.log.Warn("cached netmap not applied", "err", err)
		} else {
			d.log.Info("restored cached netmap", "generation", nm.Generation, "peers", len(nm.Peers))
		}
	} else {
		base := wg.Config{PrivateKey: d.key, ListenPort: d.state.ListenPort,
			Addresses: []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(d.state.IPv4), d.overlay.Bits())}}
		if err := dev.Configure(ctx, base); err != nil {
			return err
		}
	}
	d.startDNS(ctx)
	// The registration outlives ctx; unregisterDNS brings its own budget,
	// so an early exit (a failed local socket, say) never leaves the OS
	// routing .thawr to a resolver that is gone.
	defer d.unregisterDNS(ctx)

	srv, ln, err := d.listenLocal(ctx)
	if err != nil {
		return err
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.log.Error("local api", "err", err)
		}
	}()
	d.log.Info("client ready", "interface", dev.Name(), "backend", dev.Backend(), "ipv4", d.state.IPv4, "listen_port", d.state.ListenPort, "socket", d.opts.Socket)

	pathsDone := make(chan struct{})
	go func() {
		defer close(pathsDone)
		d.pathLoop(ctx)
	}()
	d.syncLoop(ctx)
	<-pathsDone

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelShutdown()
	_ = srv.Shutdown(shutdownCtx)
	_ = os.Remove(d.opts.Socket)
	d.log.Info("client stopped")
	return nil
}

// Stop ends Run.
func (d *Daemon) Stop() {
	d.mu.Lock()
	stop := d.stop
	d.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// Applied returns a channel receiving every netmap applied to the device.
func (d *Daemon) Applied() <-chan NetMap { return d.mapCh }

func (d *Daemon) syncLoop(ctx context.Context) {
	attempt := 0
	for {
		err := d.syncOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		d.mu.Lock()
		wanted := d.resyncWanted
		d.resyncWanted = false
		d.mu.Unlock()
		if wanted {
			d.log.Info("sync restarted", "reason", "lock key changed")
			continue
		}
		attempt++
		delay := backoffDelay(attempt, d.opts.MinBackoff, d.opts.MaxBackoff)
		msg := err.Error()
		switch status.Code(err) {
		case codes.PermissionDenied, codes.Unauthenticated:
			// Removed from the network: keep the daemon (status shows why)
			// but do not hammer the server.
			delay = d.opts.MaxBackoff
			msg = "removed from the network or credentials rejected; run `thawr client down --forget` and enrol again"
		}
		d.setDisconnected(msg, attempt, d.opts.Now().Add(delay))
		d.log.Warn("sync disconnected", "err", err, "retry_in", delay, "attempt", attempt)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if status.Code(err) != codes.PermissionDenied && status.Code(err) != codes.Unauthenticated && attempt > 10 {
			attempt = 10 // cap growth; delay already at max
		}
	}
}

// syncOnce dials, streams netmaps until the stream ends, and returns why.
func (d *Daemon) syncOnce(ctx context.Context) error {
	tlsCfg, err := PinnedTLSConfig(d.state.Fingerprint)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(d.state.Server,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithPerRPCCredentials(nodeCredentials{secret: d.state.NodeSecret}))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close() }()
	client := thawrv1.NewControlClient(conn)

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.mu.Lock()
	d.resyncNow = cancel
	var lockKey string
	if !d.lockKey.IsZero() {
		lockKey = d.lockKey.Public().String()
	}
	d.mu.Unlock()
	stream, err := client.Sync(streamCtx, &thawrv1.SyncRequest{Generation: d.generation(), ClientVersion: d.opts.Version, LockKey: lockKey})
	if err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	d.mu.Lock()
	d.client = client
	d.connected = true
	d.lastError = ""
	d.attempt, d.nextRetryAt, d.unreachableSince = 0, time.Time{}, time.Time{}
	d.lastMessage = d.opts.Now()
	d.mu.Unlock()
	d.log.Info("sync connected", "server", d.state.Server, "generation", first.GetGeneration())
	d.advertiseRoutes(ctx, client)
	defer func() {
		d.mu.Lock()
		d.connected = false
		d.client = nil
		d.unreachableSince = d.opts.Now()
		d.mu.Unlock()
	}()
	if err := d.apply(ctx, NetMapFromProto(first, d.opts.Now()), true); err != nil {
		d.log.Error("apply netmap", "err", err)
	}

	go d.reportLoop(streamCtx, client)

	for {
		msg, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("sync: %w", err)
		}
		d.mu.Lock()
		d.lastMessage = d.opts.Now()
		d.mu.Unlock()
		if msg.GetKeepalive() {
			continue
		}
		if err := d.apply(ctx, NetMapFromProto(msg, d.opts.Now()), true); err != nil {
			d.log.Error("apply netmap", "err", err)
		}
	}
}

// advertiseRoutes tells the server the complete set of prefixes this
// device carries and records what the server knows about them. It runs
// at every connect so a withdrawn set is cleared on the server too.
func (d *Daemon) advertiseRoutes(ctx context.Context, client thawrv1.ControlClient) {
	prefixes := make([]string, 0, len(d.advertise))
	for _, p := range d.advertise {
		prefixes = append(prefixes, p.String())
	}
	res, err := client.AdvertiseRoutes(ctx, &thawrv1.AdvertiseRoutesRequest{Prefixes: prefixes})
	if err != nil {
		if len(prefixes) > 0 {
			d.log.Warn("advertise routes", "err", err)
		}
		return
	}
	var advertised []AdvertisedRoute
	for _, r := range res.GetRoutes() {
		advertised = append(advertised, AdvertisedRoute{Prefix: r.GetPrefix(), Approved: r.GetApproved()})
	}
	d.mu.Lock()
	d.advertised = advertised
	d.mu.Unlock()
	for _, r := range advertised {
		if !r.Approved {
			d.log.Info("advertised route waits for approval", "prefix", r.Prefix, "hint", "thawr admin peer routes approve "+d.state.Name+" "+r.Prefix)
		}
	}
}

// apply checks nm against the pins, configures the device from what
// passed and caches the netmap as received (held entries are derived
// again from the pins on the next start).
func (d *Daemon) apply(ctx context.Context, nm NetMap, cache bool) error {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	return d.applyLocked(ctx, nm, cache)
}

// reapply applies the last received netmap again, after a trust or a
// key rotation changed how it must be applied. The netmap is read
// under applyMu, so it is the newest one and no other apply can
// interleave.
func (d *Daemon) reapply(ctx context.Context) error {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	d.mu.Lock()
	offered := d.offered
	d.mu.Unlock()
	if offered == nil {
		return nil
	}
	return d.applyLocked(ctx, *offered, false)
}

// applyLocked is apply with applyMu held.
func (d *Daemon) applyLocked(ctx context.Context, nm NetMap, cache bool) error {
	now := d.opts.Now()
	d.mu.Lock()
	key, dev, prev, exitNode := d.key, d.dev, d.held, d.exitNode
	if nm.Advertised != nil {
		d.advertised = nm.Advertised
	}
	offered := nm
	// The lock runs first: with it on, unsigned entries are held and
	// signed ones are accepted into the pins, so the pin check after
	// it only ever holds a key change the lock did not vouch for.
	rejected := d.pins.UpdateLock(nm.Lock, d.state.LockSigner)
	var held []HeldStatus
	if d.state.LockSigner != "" && d.pins.Lock() == nil {
		// Enrolled with --lock-signer and no record pinned yet: the
		// device fails closed. Trusting first-contact keys now would
		// let a hostile server hand it peers before the lock arrives.
		if rejected == "" {
			rejected = fmt.Sprintf("waiting for a lock record signed by %s; nothing is applied until it arrives", d.state.LockSigner)
		}
		nm.Peers, nm.Hub = nil, HubPeer{}
	}
	if d.pins.Enabled() {
		nm, held = d.pins.HoldUnsigned(nm, d.pins.Lock().Record, now, prev)
	}
	applied, heldKeys, err := d.pins.Apply(nm, now, prev)
	if err == nil {
		held = append(held, heldKeys...)
		sort.Slice(held, func(i, j int) bool { return held[i].Name < held[j].Name })
		d.offered, d.held, d.lockRejected = &offered, held, rejected
	}
	d.mu.Unlock()
	if err != nil {
		return err
	}
	d.logHeld(prev, held)
	if rejected != "" {
		d.lockWarn.Do(func() { d.log.Warn("lock record from server not adopted", "reason", rejected) })
	} else {
		d.lockWarn = sync.Once{}
	}
	d.warnSelfUnsigned()
	nm = applied
	cfg, err := BuildConfigWith(nm, key, d.state.ListenPort, d.overlay, exitNode)
	if err != nil {
		return err
	}
	d.devMu.Lock()
	err = dev.Configure(ctx, cfg)
	d.devMu.Unlock()
	if err != nil {
		return err
	}
	d.installRoutes(ctx, dev, cfg)
	d.installFilter(ctx, dev, nm)
	d.mu.Lock()
	d.netmap = &nm
	d.mu.Unlock()
	if err := d.syncPaths(ctx, nm, cfg); err != nil {
		d.log.Warn("path state", "err", err)
	}
	if cache {
		if err := SaveNetMap(d.opts.StateDir, offered); err != nil {
			d.log.Warn("cache netmap", "err", err)
		}
	}
	d.registerDNS(ctx)
	d.log.Debug("netmap applied", "generation", nm.Generation, "peers", len(nm.Peers))
	select {
	case d.mapCh <- nm:
	default:
	}
	return nil
}

// logHeld reports every entry that became held with this netmap and
// every one that was released by the server changing its mind.
func (d *Daemon) logHeld(prev, now []HeldStatus) {
	before := map[string]string{}
	for _, h := range prev {
		before[h.Name] = h.OfferedKey
	}
	for _, h := range now {
		if before[h.Name] != h.OfferedKey {
			if h.Reason == HeldUnsigned {
				d.log.Warn("peer not signed by the network lock; held until a signer signs it", "peer", h.Name, "offered", fingerprintOf(h.OfferedKey), "hint", "thawr client lock sign "+h.Name)
			} else {
				d.log.Warn("peer key changed; held until trusted", "peer", h.Name, "pinned", fingerprintOf(h.PinnedKey), "offered", fingerprintOf(h.OfferedKey), "hint", "thawr client trust "+h.Name)
			}
		}
		delete(before, h.Name)
	}
	for name := range before {
		d.log.Info("held peer back on its pinned key", "peer", name)
	}
}

// Trust accepts the offered keys of the named held entries ("all" for
// every one, HubName for the hub) and re-applies the last netmap.
// ErrNotHeld names an entry that is not held.
func (d *Daemon) Trust(ctx context.Context, names []string) ([]HeldStatus, error) {
	// Selection and pinning happen under one lock hold, so a netmap
	// arriving in between cannot make Trust pin a key the server no
	// longer offers; reapply then reads the newest netmap under the
	// apply lock, so the device is never configured from a stale one.
	d.mu.Lock()
	accept, err := selectHeld(d.held, names)
	if err != nil {
		d.mu.Unlock()
		return nil, err
	}
	for _, h := range accept {
		if err = d.pins.Trust(h); err != nil {
			break
		}
		d.log.Info("key trusted", "peer", h.Name, "was", fingerprintOf(h.PinnedKey), "now", fingerprintOf(h.OfferedKey))
	}
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := d.reapply(ctx); err != nil {
		return nil, err
	}
	return accept, nil
}

// selectHeld resolves names ("all", or held names with an optional
// zone suffix) against the held list.
func selectHeld(held []HeldStatus, names []string) ([]HeldStatus, error) {
	var accept []HeldStatus
	for _, name := range names {
		name = stripZone(name)
		if name == "all" {
			for _, h := range held {
				if h.Reason != HeldUnsigned {
					accept = append(accept, h)
				}
			}
			continue
		}
		i := slices.IndexFunc(held, func(h HeldStatus) bool { return h.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("%w: %s is not held", ErrNotHeld, name)
		}
		if held[i].Reason == HeldUnsigned {
			return nil, fmt.Errorf("%w: %s is unsigned, not merely changed; a signer must run: thawr client lock sign %s", ErrNotHeld, name, name)
		}
		accept = append(accept, held[i])
	}
	if len(accept) == 0 {
		return nil, fmt.Errorf("%w: no key is held for a changed key", ErrNotHeld)
	}
	return accept, nil
}

// installFilter applies the netmap's receiver-side policy to the
// device; a device without filter support is reported once.
func (d *Daemon) installFilter(ctx context.Context, dev wg.Device, nm NetMap) {
	fd, ok := dev.(wg.Filterable)
	if !ok {
		d.filterWarn.Do(func() {
			d.log.Warn("device cannot filter; policy is enforced by key distribution only", "backend", dev.Backend())
		})
		return
	}
	set := FilterSetFor(nm, dev.Name(), d.selfIP, d.overlay, d.advertise)
	d.devMu.Lock()
	err := fd.SetFilter(ctx, set)
	d.devMu.Unlock()
	if err != nil {
		d.log.Error("install filter", "err", err)
		return
	}
	d.log.Debug("filter installed", "rules", len(set.Rules), "visible", len(set.Visible))
}

// installRoutes puts the prefixes reached through peers, the exit
// node's default route included, into the OS routing table; a device
// without route support is reported once.
func (d *Daemon) installRoutes(ctx context.Context, dev wg.Device, cfg wg.Config) {
	rd, ok := dev.(wg.Routable)
	if !ok {
		if len(RoutesOf(cfg, d.overlay)) > 0 {
			d.routesWarn.Do(func() {
				d.log.Warn("device cannot install routes; subnet routes and exit nodes are unavailable", "backend", dev.Backend())
			})
		}
		return
	}
	routes := RoutesOf(cfg, d.overlay)
	d.devMu.Lock()
	err := rd.SetRoutes(ctx, routes)
	d.devMu.Unlock()
	if err != nil {
		d.log.Error("install routes", "err", err)
		return
	}
	if len(routes) > 0 {
		d.log.Debug("routes installed", "routes", routes)
	}
}

// Errors of the exit-node selection.
var (
	// ErrNotExitNode means the named peer is not an exit node this device
	// may use (no flag in the netmap, or held).
	ErrNotExitNode = errors.New("not an exit node this device may use")
)

// ExitNodeOff clears the exit-node selection.
const ExitNodeOff = "off"

// SetExitNode routes this device's internet traffic through the named
// peer (ExitNodeOff or "" for none), persists the choice and re-applies
// the netmap. The peer must be flagged as exit node in the current
// netmap and not held.
func (d *Daemon) SetExitNode(ctx context.Context, name string) (ExitNodeStatus, error) {
	name = stripZone(name)
	if name == ExitNodeOff {
		name = ""
	}
	d.mu.Lock()
	nm := d.netmap
	if name != "" {
		found := false
		if nm != nil {
			for _, p := range nm.Peers {
				if p.Name == name && p.ExitNode && !p.ViaHub {
					found = true
				}
			}
		}
		if !found {
			d.mu.Unlock()
			return ExitNodeStatus{}, fmt.Errorf("%w: %s", ErrNotExitNode, name)
		}
	}
	d.exitNode, d.state.ExitNode = name, name
	st := d.state
	d.mu.Unlock()
	if err := SaveState(d.opts.StateDir, st); err != nil {
		return ExitNodeStatus{}, err
	}
	if err := d.reapply(ctx); err != nil {
		return ExitNodeStatus{}, err
	}
	if name == "" {
		d.log.Info("exit node off")
	} else {
		d.log.Info("exit node selected", "peer", name)
	}
	return d.Status(ctx).ExitNode, nil
}

func (d *Daemon) generation() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.netmap == nil {
		return 0
	}
	return d.netmap.Generation
}

// setDisconnected records why the last attempt failed and when the next
// one is due; the first failure stamps unreachableSince.
func (d *Daemon) setDisconnected(msg string, attempt int, next time.Time) {
	d.mu.Lock()
	d.lastError, d.attempt, d.nextRetryAt = msg, attempt, next
	if d.unreachableSince.IsZero() {
		d.unreachableSince = d.opts.Now()
	}
	d.mu.Unlock()
}

// RotateKey generates a new WireGuard key, registers it with the server
// and switches the device to it.
func (d *Daemon) RotateKey(ctx context.Context) error {
	d.mu.Lock()
	client := d.client
	d.mu.Unlock()
	if client == nil {
		return errors.New("client: not connected to the server")
	}
	newKey, err := wg.GenerateKey()
	if err != nil {
		return err
	}
	signer, signature, err := d.selfRotation(newKey)
	if err != nil {
		return err
	}
	if _, err := client.RotateKey(ctx, &thawrv1.RotateKeyRequest{NewPublicKey: newKey.PublicKey().String(), SignerKey: signer, Signature: signature}); err != nil {
		return fmt.Errorf("client: rotate key: %w", err)
	}
	if err := SaveKey(d.opts.StateDir, newKey); err != nil {
		return err
	}
	d.mu.Lock()
	d.key = newKey
	d.mu.Unlock()
	if err := d.reapply(ctx); err != nil {
		return err
	}
	if signer != "" {
		d.log.Info("key rotated and signed; other devices switch without a trust step", "key", wg.Fingerprint(newKey.PublicKey()))
	} else {
		d.log.Info("key rotated; other devices hold this peer until they trust the new key", "key", wg.Fingerprint(newKey.PublicKey()), "hint", "thawr client trust "+d.state.Name)
	}
	return nil
}

// warnSelfUnsigned logs once, while it holds, that other devices hold
// this one because no signer signed its record yet.
func (d *Daemon) warnSelfUnsigned() {
	d.mu.Lock()
	st := d.lockStatusLocked()
	d.mu.Unlock()
	if st.Enabled && !st.SelfSigned {
		d.selfUnsignedWarn.Do(func() {
			d.log.Warn("this device is not signed by the network lock; other devices hold it until a signer signs it", "hint", "thawr client lock sign "+d.state.Name)
		})
		return
	}
	d.selfUnsignedWarn = sync.Once{}
}

// resync ends the current sync stream so the next one reports the
// current lock key; the loop reconnects at once.
func (d *Daemon) resync() {
	d.mu.Lock()
	cancel := d.resyncNow
	if cancel != nil {
		d.resyncWanted = true
	}
	d.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// backoffDelay is exponential from min with ±20 % jitter, capped at max.
func backoffDelay(attempt int, minDelay, maxDelay time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := float64(minDelay) * math.Pow(2, float64(attempt-1))
	if d > float64(maxDelay) {
		d = float64(maxDelay)
	}
	var b [1]byte
	_, _ = rand.Read(b[:])
	jitter := (float64(b[0])/255 - 0.5) * 0.4 // -0.2 .. +0.2
	d *= 1 + jitter
	if d < float64(minDelay) {
		d = float64(minDelay)
	}
	if d > float64(maxDelay) {
		d = float64(maxDelay)
	}
	return time.Duration(d)
}

// nodeCredentials sends the node secret as a bearer token per RPC.
type nodeCredentials struct{ secret string }

func (c nodeCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + c.secret}, nil
}

func (nodeCredentials) RequireTransportSecurity() bool { return true }

func (d *Daemon) listenLocal(ctx context.Context) (*http.Server, net.Listener, error) {
	if err := os.MkdirAll(dirOf(d.opts.Socket), 0o755); err != nil { //nolint:gosec // socket dir is not secret; the socket itself is 0660
		return nil, nil, fmt.Errorf("client: socket dir: %w", err)
	}
	if err := os.Remove(d.opts.Socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("client: remove stale socket: %w", err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", d.opts.Socket)
	if err != nil {
		return nil, nil, fmt.Errorf("client: listen %s: %w", d.opts.Socket, err)
	}
	if err := secureSocket(d.opts.Socket); err != nil {
		d.log.Warn("socket permissions", "err", err)
	}
	srv := &http.Server{Handler: d.localHandler(), ReadHeaderTimeout: 5 * time.Second}
	return srv, ln, nil
}
