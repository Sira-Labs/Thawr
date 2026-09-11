package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/store"
	"github.com/thedatadudech/thawr/internal/wg"
)

// Registry lists and manages registered peers.
type Registry struct {
	store  *store.Store
	log    *slog.Logger
	now    func() time.Time
	notify Notifier
	// overlay and tagAllowed serve CreateStatic.
	overlay    netip.Prefix
	tagAllowed TagAllowed
	audit      *Auditor
	lock       *LockService
}

// WithLock lets a signer vouch for its own key on rotation.
func (r *Registry) WithLock(l *LockService) *Registry {
	r.lock = l
	return r
}

// SignedRotation is the signature a signer sends over its new key.
type SignedRotation struct {
	Signer    lock.PublicKey
	Signature lock.Signature
}

// NewRegistry builds the registry service. notify may be nil.
func NewRegistry(st *store.Store, log *slog.Logger) *Registry {
	return &Registry{store: st, log: log, now: time.Now}
}

// WithNotifier sets the notifier told after every persistent change.
func (r *Registry) WithNotifier(n Notifier) *Registry {
	r.notify = n
	return r
}

// WithClock sets the time source.
func (r *Registry) WithClock(now func() time.Time) *Registry {
	r.now = now
	return r
}

// WithAuditor records every mutation in the audit log.
func (r *Registry) WithAuditor(a *Auditor) *Registry {
	r.audit = a
	return r
}

func (r *Registry) changed() {
	if r.notify != nil {
		r.notify.Changed()
	}
}

// List returns peers visible to the principal: all for admins, own for
// members.
func (r *Registry) List(ctx context.Context, by Principal) ([]store.Peer, error) {
	all, err := r.store.Peers().List(ctx)
	if err != nil {
		return nil, err
	}
	if by.IsAdmin() {
		return all, nil
	}
	var own []store.Peer
	for _, p := range all {
		if p.OwnerID == by.UserID {
			own = append(own, p)
		}
	}
	return own, nil
}

// Get returns one peer by name, subject to the same visibility as List.
func (r *Registry) Get(ctx context.Context, by Principal, name string) (store.Peer, error) {
	p, err := r.store.Peers().GetByName(ctx, name)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !by.IsAdmin() && p.OwnerID != by.UserID) {
		return store.Peer{}, fmt.Errorf("peer %q: %w", name, ErrNotFound)
	}
	return p, err
}

// Rename changes a peer's name (admins only).
func (r *Registry) Rename(ctx context.Context, by Principal, name, newName string) error {
	if !by.IsAdmin() {
		return ErrForbidden
	}
	if !validLabel(newName) {
		return fmt.Errorf("%w: name %q must be a DNS label", ErrValidation, newName)
	}
	p, err := r.Get(ctx, by, name)
	if err != nil {
		return err
	}
	err = r.store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.Peers().Rename(ctx, p.ID, newName); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("%w: name %q is taken", ErrValidation, newName)
			}
			return err
		}
		if err := r.audit.Record(ctx, tx, by, AuditPeerRename, p.ID, map[string]string{"from": name, "to": newName}); err != nil {
			return err
		}
		_, err := tx.Meta().IncrementGeneration(ctx)
		return err
	})
	if err != nil {
		return err
	}
	r.changed()
	r.log.Info("peer renamed", "peer_id", p.ID, "from", name, "to", newName, "by", by.Name)
	return nil
}

// Delete removes a peer (admins only) and bumps the netmap generation so
// every client drops it. Closing its streams is spec 003's job.
func (r *Registry) Delete(ctx context.Context, by Principal, name string) error {
	if !by.IsAdmin() {
		return ErrForbidden
	}
	p, err := r.Get(ctx, by, name)
	if err != nil {
		return err
	}
	if err := r.deletePeer(ctx, p.ID, by, AuditPeerDelete, p.Name); err != nil {
		return err
	}
	r.log.Info("peer deleted", "peer", name, "peer_id", p.ID, "by", by.Name)
	return nil
}

// deletePeer removes the peer, records action for the principal and
// bumps the generation in one transaction. The name is looked up when
// the caller does not know it (a peer leaving by id).
func (r *Registry) deletePeer(ctx context.Context, id string, by Principal, action, name string) error {
	err := r.store.InTx(ctx, func(tx *store.Store) error {
		if name == "" {
			p, err := tx.Peers().GetByID(ctx, id)
			if err != nil {
				return err
			}
			name = p.Name
		}
		if err := tx.Peers().Delete(ctx, id); err != nil {
			return err
		}
		if err := tx.Signatures().DeletePeer(ctx, id); err != nil {
			return err
		}
		if by.Name == "" {
			by = PeerPrincipal(name)
		}
		if err := r.audit.Record(ctx, tx, by, action, id, map[string]string{"name": name}); err != nil {
			return err
		}
		_, err := tx.Meta().IncrementGeneration(ctx)
		return err
	})
	if err != nil {
		return err
	}
	r.changed()
	return nil
}

// PeerByNodeSecret authenticates an agent peer by its node secret.
func (r *Registry) PeerByNodeSecret(ctx context.Context, secret string) (store.Peer, error) {
	if secret == "" {
		return store.Peer{}, ErrForbidden
	}
	p, err := r.store.Peers().GetByNodeSecretHash(ctx, hashSecret(secret))
	if errors.Is(err, store.ErrNotFound) {
		return store.Peer{}, ErrForbidden
	}
	return p, err
}

// RotateKey replaces a peer's WireGuard public key and bumps the
// generation so every client switches within one netmap. A signer may
// pass its signature over the new key (spec 012); it is verified and
// stored in the same transaction, so other devices never see the new
// key unsigned.
func (r *Registry) RotateKey(ctx context.Context, peerID, newPublicKey string, signed *SignedRotation) (int64, error) {
	if _, err := parsePublicKey(newPublicKey); err != nil {
		return 0, err
	}
	var gen int64
	err := r.store.InTx(ctx, func(tx *store.Store) error {
		p, err := tx.Peers().GetByID(ctx, peerID)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("peer %s: %w", peerID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		var sig *store.PeerSignature
		if signed != nil {
			if r.lock == nil {
				return fmt.Errorf("%w: this server has no network lock", ErrValidation)
			}
			row, err := r.lock.VerifyRotation(ctx, tx, p, newPublicKey, signed.Signer, signed.Signature)
			if err != nil {
				return err
			}
			sig = &row
		}
		if err := tx.Peers().SetPublicKey(ctx, peerID, newPublicKey); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("%w: key already in use", ErrValidation)
			}
			return err
		}
		if sig != nil {
			if err := tx.Signatures().Put(ctx, *sig); err != nil {
				return err
			}
		}
		gen, err = tx.Meta().IncrementGeneration(ctx)
		if err != nil {
			return err
		}
		key, _ := parsePublicKey(newPublicKey)
		return r.audit.Record(ctx, tx, PeerPrincipal(p.Name), AuditPeerRotateKey, peerID,
			map[string]string{"name": p.Name, "key": wg.Fingerprint(key), "generation": strconv.FormatInt(gen, 10)})
	})
	if err != nil {
		return 0, err
	}
	r.changed()
	r.log.Info("peer key rotated", "peer_id", peerID, "generation", gen)
	return gen, nil
}

// Leave removes a peer at its own request.
func (r *Registry) Leave(ctx context.Context, peerID string) error {
	if err := r.deletePeer(ctx, peerID, Principal{}, AuditPeerLeave, ""); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("peer %s: %w", peerID, ErrNotFound)
		}
		return err
	}
	r.log.Info("peer left", "peer_id", peerID)
	return nil
}

// Touch records that a peer was seen now.
func (r *Registry) Touch(ctx context.Context, peerID string) error {
	return r.store.Peers().Touch(ctx, peerID, r.now())
}

// SetClientVersion records the version a client reported on sync.
func (r *Registry) SetClientVersion(ctx context.Context, peerID, version string) error {
	return r.store.Peers().SetClientVersion(ctx, peerID, version)
}

// Generation returns the current netmap generation.
func (r *Registry) Generation(ctx context.Context) (int64, error) {
	return r.store.Meta().Generation(ctx)
}
