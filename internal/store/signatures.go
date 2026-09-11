package store

import (
	"context"
	"fmt"
	"time"
)

// MetaLockRecord is the meta key holding the signed lock record as JSON.
const MetaLockRecord = "lock_record"

// PeerSignature is one lock key's signature over a peer's record for a
// given WireGuard key. PeerID is a peer id or "hub".
type PeerSignature struct {
	PeerID    string
	PublicKey string
	SignerKey string
	Signature string
	SignedAt  time.Time
}

// Signatures accesses the peer_signatures table.
type Signatures struct {
	q querier
}

// Put inserts or replaces a signature.
func (s *Signatures) Put(ctx context.Context, sig PeerSignature) error {
	if sig.PeerID == "" || sig.PublicKey == "" || sig.SignerKey == "" || sig.Signature == "" {
		return fmt.Errorf("store: signature needs peer, key, signer and signature: %+v", sig)
	}
	_, err := s.q.ExecContext(ctx,
		`INSERT INTO peer_signatures (peer_id, public_key, signer_key, signature, signed_at) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(peer_id, public_key, signer_key) DO UPDATE SET signature = excluded.signature, signed_at = excluded.signed_at`,
		sig.PeerID, sig.PublicKey, sig.SignerKey, sig.Signature, formatTime(sig.SignedAt))
	if err != nil {
		return fmt.Errorf("store: put signature for %s: %w", sig.PeerID, err)
	}
	return nil
}

// ListAll returns every signature, ordered by peer id then signer.
func (s *Signatures) ListAll(ctx context.Context) ([]PeerSignature, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT peer_id, public_key, signer_key, signature, signed_at FROM peer_signatures ORDER BY peer_id, signer_key`)
	if err != nil {
		return nil, fmt.Errorf("store: list signatures: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []PeerSignature
	for rows.Next() {
		var (
			sig PeerSignature
			at  string
		)
		if err := rows.Scan(&sig.PeerID, &sig.PublicKey, &sig.SignerKey, &sig.Signature, &at); err != nil {
			return nil, fmt.Errorf("store: scan signature: %w", err)
		}
		sig.SignedAt = parseTime(at)
		out = append(out, sig)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list signatures: %w", err)
	}
	return out, nil
}

// DeletePeer removes every signature of a peer (on delete).
func (s *Signatures) DeletePeer(ctx context.Context, peerID string) error {
	if _, err := s.q.ExecContext(ctx, `DELETE FROM peer_signatures WHERE peer_id = ?`, peerID); err != nil {
		return fmt.Errorf("store: delete signatures of %s: %w", peerID, err)
	}
	return nil
}

// DeleteKey removes the signatures over one of a peer's keys, used when
// the peer rotates away from it.
func (s *Signatures) DeleteKey(ctx context.Context, peerID, publicKey string) error {
	if _, err := s.q.ExecContext(ctx, `DELETE FROM peer_signatures WHERE peer_id = ? AND public_key = ?`, peerID, publicKey); err != nil {
		return fmt.Errorf("store: delete signatures of %s over %s: %w", peerID, publicKey, err)
	}
	return nil
}

// DeleteAll removes every signature (when the lock is disabled and
// re-initialised).
func (s *Signatures) DeleteAll(ctx context.Context) error {
	if _, err := s.q.ExecContext(ctx, `DELETE FROM peer_signatures`); err != nil {
		return fmt.Errorf("store: delete signatures: %w", err)
	}
	return nil
}
