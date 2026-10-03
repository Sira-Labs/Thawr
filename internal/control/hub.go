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
	// wants holds reach requests: target peer id -> requesting peer id
	// -> request (specs 004, 005).
	wants map[string]map[string]wantReq
	// wantSeq numbers the wakes for reach requests, so a receiver can
	// tell a new request from one it already acted on. It starts at the
	// hub's creation time in nanoseconds: a client keeps the last number
	// it saw across reconnects, and a restarted server must not hand out
	// that number again for a new request.
	wantSeq uint64
}

// Reach requests ("from is trying to reach to"): a request stays in
// to's netmaps for wantTTL; a repeated request wakes to again only
// after wantRepeat.
const (
	wantTTL    = 30 * time.Second
	wantRepeat = 5 * time.Second
)

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
		wants:    map[string]map[string]wantReq{},
		wantSeq:  uint64(max(now().UnixNano(), 0)),
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

// Forget drops presence and reach requests for a deleted peer.
func (h *Hub) Forget(peerID string) {
	h.mu.Lock()
	delete(h.presence, peerID)
	delete(h.wants, peerID)
	for to, from := range h.wants {
		delete(from, peerID)
		if len(from) == 0 {
			delete(h.wants, to)
		}
	}
	h.mu.Unlock()
}

// wantReq is one reach request: when it was last made (for wantTTL) and
// when it last woke the target (for wantRepeat).
type wantReq struct {
	at, woke time.Time
	seq      uint64 // of the latest wake
}

// Want records that peer from is trying to reach peer to (it probes
// to's candidates or waits for it on the relay) and wakes to's Sync
// streams at once, without a new generation, so to's next netmap asks
// it to reach from as well. Hole punching needs both sides at once, and
// a peer with no traffic of its own would otherwise neither punch nor
// join the relay (specs 004, 005).
//
// Only a peer with an open stream is recorded, since nothing else can be
// woken; with expired requests pruned on the way, the table never holds
// more than connected peers times their visible peers, whatever ids a
// client reports.
func (h *Hub) Want(to, from string) {
	h.mu.Lock()
	if e := h.presence[to]; e == nil || e.streams == 0 {
		h.mu.Unlock()
		return
	}
	now := h.now()
	reqs := h.wants[to]
	if reqs == nil {
		reqs = map[string]wantReq{}
		h.wants[to] = reqs
	}
	for id, r := range reqs {
		if now.Sub(r.at) >= wantTTL {
			delete(reqs, id)
		}
	}
	r, seen := reqs[from]
	// The repeat gate counts from the last wake, not the last request:
	// a sender repeating faster than wantRepeat still wakes the target
	// every wantRepeat.
	wake := !seen || now.Sub(r.woke) >= wantRepeat
	r.at = now
	if wake {
		h.wantSeq++
		r.woke, r.seq = now, h.wantSeq
	}
	reqs[from] = r
	if wake {
		for s := range h.subs {
			if s.peerID != to {
				continue
			}
			select {
			case s.ch <- struct{}{}:
			default: // already has a pending wake-up
			}
		}
	}
	h.mu.Unlock()
	if wake {
		h.log.Debug("peer wanted", "peer_id", to, "from", from)
	}
}

// Wanted reports whether peer from asked to reach peer to within the
// last wantTTL.
func (h *Hub) Wanted(to, from string) bool { return h.WantSeq(to, from) != 0 }

// WantSeq returns the sequence number of the latest wake for peer
// from's request to reach peer to, or 0 when there is no request within
// the last wantTTL. A changed number is a new request: the receiver
// acts on it once, however long the request stays live.
func (h *Hub) WantSeq(to, from string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.wants[to][from]
	if !ok {
		return 0
	}
	if h.now().Sub(r.at) < wantTTL {
		return r.seq
	}
	delete(h.wants[to], from)
	if len(h.wants[to]) == 0 {
		delete(h.wants, to)
	}
	return 0
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
