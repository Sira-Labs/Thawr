package server

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/config"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/dns"
	"github.com/sira-labs/thawr/internal/store"
)

// dnsPort is where the hub resolver listens on the hub address.
const dnsPort = 53

// registrySource answers zone lookups for the hub resolver from the peer
// registry, cached per hub generation, and shows a requesting peer only
// the peers the policy makes visible to it. The hub's own name is
// visible to everyone on the overlay; an unknown requester sees nothing
// else. IPv6 addresses (spec 015) are answered only between peers that
// are both IPv6 capable, as the netmap lists them.
type registrySource struct {
	st         *store.Store
	visibility control.Visibility
	generation func() int64
	hub        netip.Addr
	hub6       netip.Addr

	mu     sync.Mutex
	gen    int64
	byName map[string]store.Peer
	byAddr map[netip.Addr]store.Peer
}

// newRegistrySource answers for the hub at hub and, with the IPv6
// overlay, hub6 (zero without it).
func newRegistrySource(st *store.Store, vis control.Visibility, generation func() int64, hub, hub6 netip.Addr) *registrySource {
	return &registrySource{st: st, visibility: vis, generation: generation, hub: hub, hub6: hub6, gen: -1}
}

// Lookup implements dns.Source.
func (r *registrySource) Lookup(ctx context.Context, from netip.Addr, name string) ([]netip.Addr, bool) {
	if err := r.refresh(ctx); err != nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v6 := r.ipv6CapableLocked(from)
	if name == client.HubName {
		out := []netip.Addr{r.hub}
		if v6 && r.hub6.IsValid() {
			out = append(out, r.hub6)
		}
		return out, true
	}
	target, ok := r.byName[strings.ToLower(name)]
	if !ok || !r.visibleLocked(from, target) {
		return nil, false
	}
	addr, err := netip.ParseAddr(target.IPv4)
	if err != nil {
		return nil, false
	}
	out := []netip.Addr{addr}
	if a6, ok := peerIPv6(target); ok && v6 {
		out = append(out, a6)
	}
	return out, true
}

// ipv6CapableLocked reports whether the requester at from may be told
// IPv6 addresses: the server itself, or a peer that is IPv6 capable.
func (r *registrySource) ipv6CapableLocked(from netip.Addr) bool {
	if from == r.hub || from == r.hub6 || from.IsLoopback() {
		return true
	}
	requester, ok := r.byAddr[from]
	return ok && requester.IPv6Capable
}

// peerIPv6 is p's IPv6 overlay address when p is IPv6 capable.
func peerIPv6(p store.Peer) (netip.Addr, bool) {
	if !p.IPv6Capable {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(p.IPv6)
	return a, err == nil && a.Is6()
}

// Reverse implements dns.Source.
func (r *registrySource) Reverse(ctx context.Context, from, addr netip.Addr) (string, bool) {
	if addr == r.hub || (r.hub6.IsValid() && addr == r.hub6) {
		return client.HubName, true
	}
	if err := r.refresh(ctx); err != nil {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	target, ok := r.byAddr[addr]
	if !ok || !r.visibleLocked(from, target) {
		return "", false
	}
	return target.Name, true
}

// visibleLocked decides whether the peer at from may learn target. The
// hub itself (the server asking) sees everything; a peer sees itself and
// what the policy grants.
func (r *registrySource) visibleLocked(from netip.Addr, target store.Peer) bool {
	if from == r.hub || from.IsLoopback() {
		return true
	}
	requester, ok := r.byAddr[from]
	if !ok {
		return false
	}
	return requester.ID == target.ID || r.visibility.Visible(requester, target)
}

// refresh reloads the registry when the hub generation moved.
func (r *registrySource) refresh(ctx context.Context) error {
	gen := r.generation()
	r.mu.Lock()
	current := r.gen
	r.mu.Unlock()
	if gen == current {
		return nil
	}
	peers, err := r.st.Peers().List(ctx)
	if err != nil {
		return fmt.Errorf("server: dns: list peers: %w", err)
	}
	byName := make(map[string]store.Peer, len(peers))
	byAddr := make(map[netip.Addr]store.Peer, len(peers))
	for _, p := range peers {
		byName[strings.ToLower(p.Name)] = p
		if a, err := netip.ParseAddr(p.IPv4); err == nil {
			byAddr[a] = p
		}
		if a, ok := peerIPv6(p); ok {
			byAddr[a] = p
		}
	}
	r.mu.Lock()
	r.gen, r.byName, r.byAddr = gen, byName, byAddr
	r.mu.Unlock()
	return nil
}

// startDNS binds the hub resolver when dns.enabled. A bind failure is a
// start-up error: the operator asked for the resolver. It returns the
// function that stops serving.
func (s *Server) startDNS(ctx context.Context) (stop func(), err error) {
	if !s.cfg.DNS.Enabled {
		return func() {}, nil
	}
	upstreams := s.cfg.DNSUpstreams()
	if len(upstreams) == 0 {
		upstreams = config.SystemUpstreams()
	}
	addr := netip.AddrPortFrom(s.cfg.HubAddr().Addr(), dnsPort)
	udp, tcp, err := s.deps.DNSListen(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("server: dns: %w (set dns.enabled: false to run without names)", err)
	}
	srv := dns.NewServer(dns.Options{Source: s.dnsSource, Upstreams: upstreams, Allow: s.cfg.OverlayPrefix(), Reverse6: s.overlay6(), Logger: s.log})
	serveCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	listen := addr.String()
	s.dnsListen.Store(&listen)
	go func() {
		defer close(done)
		if err := srv.Serve(serveCtx, udp, tcp); err != nil {
			// A listener died underneath us: stop advertising the
			// resolver in status; the operator sees the error in the log.
			empty := ""
			s.dnsListen.Store(&empty)
			s.log.Error("dns: hub resolver stopped", "listen", listen, "err", err)
		}
	}()
	ups := make([]string, 0, len(upstreams))
	for _, u := range upstreams {
		ups = append(ups, u.String())
	}
	s.dnsNoUpstream = len(ups) == 0
	if len(ups) == 0 {
		s.log.Warn("dns: hub resolver serves only the zone; no upstream found, phones resolve only .thawr names", "listen", addr.String())
	} else {
		s.log.Info("dns: hub resolver ready", "zone", dns.Zone, "listen", addr.String(), "upstreams", strings.Join(ups, ","))
	}
	return func() { cancel(); <-done }, nil
}
