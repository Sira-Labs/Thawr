package control

import (
	"context"
	"fmt"
	"sync"

	"github.com/sira-labs/thawr/internal/store"
)

// KeyVisibility answers visibility questions by public key for the
// relay. It caches the peer table per netmap generation, so a deleted
// peer disappears with the next generation and lookups stay cheap.
type KeyVisibility struct {
	store      *store.Store
	visibility Visibility
	generation func() int64

	mu    sync.Mutex
	gen   int64
	byKey map[string]store.Peer
}

// NewKeyVisibility builds a cache over st with the given rule.
func NewKeyVisibility(st *store.Store, vis Visibility, generation func() int64) *KeyVisibility {
	return &KeyVisibility{store: st, visibility: vis, generation: generation, gen: -1}
}

// Visible reports whether the peers with public keys src and dst may
// exchange packets. Unknown keys are never visible.
func (v *KeyVisibility) Visible(ctx context.Context, src, dst string) (bool, error) {
	peers, err := v.peers(ctx)
	if err != nil {
		return false, err
	}
	a, ok := peers[src]
	if !ok {
		return false, nil
	}
	b, ok := peers[dst]
	if !ok {
		return false, nil
	}
	return v.visibility.Visible(a, b), nil
}

func (v *KeyVisibility) peers(ctx context.Context) (map[string]store.Peer, error) {
	gen := v.generation()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.byKey != nil && gen == v.gen {
		return v.byKey, nil
	}
	list, err := v.store.Peers().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("control: relay visibility: %w", err)
	}
	m := make(map[string]store.Peer, len(list))
	for _, p := range list {
		m[p.PublicKey] = p
	}
	v.byKey, v.gen = m, gen
	return m, nil
}
