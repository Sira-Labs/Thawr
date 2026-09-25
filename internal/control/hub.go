package control

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/sira-labs/thawr/internal/store"
)

// Notifier is told after a persistent change so subscribers wake up.
type Notifier interface {
	Changed()
}

// HubOptions tune presence and coalescing; zero values are production.
type HubOptions struct {
	// Coalesce delays wake-ups so bursts become one netmap.
	Coalesce time.Duration
	// OfflineAfter is the grace period after a stream drops before the
	// peer counts as offline.
	OfflineAfter time.Duration
	// KeepaliveInterval is the resend period of an unchanged netmap.
	KeepaliveInterval time.Duration
}

func (o HubOptions) withDefaults() HubOptions {
	if o.Coalesce == 0 {
		o.Coalesce = 200 * time.Millisecond
	}
	if o.OfflineAfter == 0 {
		o.OfflineAfter = 90 * time.Second
	}
	if o.KeepaliveInterval == 0 {
		o.KeepaliveInterval = 30 * time.Second
	}
	return o
}

// Hub is the in-memory heart of key distribution: the netmap sequence,
// which peers are online, and the wake-up channels of open Sync
// streams. It implements Notifier and Presence.
type Hub struct {
	store *store.Store
	now   func() time.Time
	log   *slog.Logger
	opts  HubOptions

	mu       sync.Mutex
	sequence int64
	subs     map[*subscriber]struct{}
	presence map[string]*presenceEntry
	pending  bool
	timer    *time.Timer
}

type subscriber struct {
	peerID string
	ch     chan struct{}
}

type presenceEntry struct {
	streams        int
	disconnectedAt time.Time
	online         bool
}

// NewHub builds a hub whose sequence starts at the persisted generation.
func NewHub(ctx context.Context, st *store.Store, now func() time.Time, log *slog.Logger, opts HubOptions) (*Hub, error) {
	gen, err := st.Meta().Generation(ctx)
	if err != nil {
		return nil, err
	}
	return &Hub{
		store:    st,
		now:      now,
		log:      log,
		opts:     opts.withDefaults(),
		sequence: gen,
		subs:     map[*subscriber]struct{}{},
		presence: map[string]*presenceEntry{},
	}, nil
}

// Options returns the effective options.
func (h *Hub) Options() HubOptions { return h.opts }

// Generation returns the current netmap sequence.
func (h *Hub) Generation() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sequence
}

// Subscribe registers a Sync stream. The channel receives one value per
// coalesced change; the returned function unsubscribes.
func (h *Hub) Subscribe(peerID string) (<-chan struct{}, func()) {
	s := &subscriber{peerID: peerID, ch: make(chan struct{}, 1)}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s.ch, func() {
		h.mu.Lock()
		delete(h.subs, s)
		h.mu.Unlock()
	}
}

// Changed bumps the sequence at once (catching up with the database
// generation after a persistent change) and wakes every subscriber
// after the coalescing delay, so a burst becomes one netmap.
func (h *Hub) Changed() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sequence++
	if gen, err := h.store.Meta().Generation(context.Background()); err == nil && gen > h.sequence {
		h.sequence = gen
	}
	if h.pending {
		return
	}
	h.pending = true
	h.timer = time.AfterFunc(h.opts.Coalesce, h.flush)
}

func (h *Hub) flush() {
	h.mu.Lock()
	h.pending = false
	seq := h.sequence
	for s := range h.subs {
		select {
		case s.ch <- struct{}{}:
		default: // already has a pending wake-up
		}
	}
	h.mu.Unlock()
	h.log.Debug("netmap changed", "generation", seq)
}

// Connected marks a peer online because a Sync stream opened.
func (h *Hub) Connected(peerID string) {
	h.mu.Lock()
	e := h.presence[peerID]
	if e == nil {
		e = &presenceEntry{}
		h.presence[peerID] = e
	}
	e.streams++
	wasOnline := e.online
	e.online = true
	h.mu.Unlock()
	if !wasOnline {
		h.Changed()
	}
}

// Disconnected records a closed stream; the peer stays online for the
// grace period so reconnects do not flap.
func (h *Hub) Disconnected(peerID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.presence[peerID]
	if e == nil {
		return
	}
	if e.streams > 0 {
		e.streams--
	}
	if e.streams == 0 {
		e.disconnectedAt = h.now()
	}
}

// Online implements Presence.
func (h *Hub) Online(peerID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.presence[peerID]
	return e != nil && e.online
}

// Forget drops presence for a deleted peer.
func (h *Hub) Forget(peerID string) {
	h.mu.Lock()
	delete(h.presence, peerID)
	h.mu.Unlock()
}

// Sweep marks peers offline whose last stream closed longer than
// OfflineAfter ago and notifies when any changed. Call it periodically.
func (h *Hub) Sweep() {
	h.mu.Lock()
	now := h.now()
	changed := false
	for id, e := range h.presence {
		if e.online && e.streams == 0 && now.Sub(e.disconnectedAt) >= h.opts.OfflineAfter {
			e.online = false
			changed = true
			h.log.Info("peer offline", "peer_id", id)
		}
	}
	h.mu.Unlock()
	if changed {
		h.Changed()
	}
}

// OnlineCount returns how many peers are online.
func (h *Hub) OnlineCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, e := range h.presence {
		if e.online {
			n++
		}
	}
	return n
}

// RunSweeper calls Sweep every interval until ctx ends.
func (h *Hub) RunSweeper(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.Sweep()
		}
	}
}
