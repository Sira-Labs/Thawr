package store

import (
	"context"
	"fmt"
	"time"
)

// PeerRoute is one prefix a peer advertises (spec 013). Approved is
// true once an admin approved it; ApprovedBy names that admin.
type PeerRoute struct {
	PeerID       string
	Prefix       string
	AdvertisedAt time.Time
	Approved     bool
	ApprovedAt   time.Time
	ApprovedBy   string
}

// Routes accesses the peer_routes table.
type Routes struct {
	q querier
}

// Replace makes prefixes the complete advertised set of a peer: missing
// ones are inserted unapproved, stored ones not in the list are removed
// (approval included). It returns what was added and what was removed.
func (r *Routes) Replace(ctx context.Context, peerID string, prefixes []string, now time.Time) (added, removed []string, err error) {
	current, err := r.ListPeer(ctx, peerID)
	if err != nil {
		return nil, nil, err
	}
	want := make(map[string]bool, len(prefixes))
	for _, p := range prefixes {
		want[p] = true
	}
	have := make(map[string]bool, len(current))
	for _, c := range current {
		have[c.Prefix] = true
		if !want[c.Prefix] {
			if _, err := r.q.ExecContext(ctx, `DELETE FROM peer_routes WHERE peer_id = ? AND prefix = ?`, peerID, c.Prefix); err != nil {
				return nil, nil, fmt.Errorf("store: withdraw route %s of %s: %w", c.Prefix, peerID, err)
			}
			removed = append(removed, c.Prefix)
		}
	}
	for _, p := range prefixes {
		if have[p] {
			continue
		}
		if _, err := r.q.ExecContext(ctx, `INSERT INTO peer_routes (peer_id, prefix, advertised_at) VALUES (?, ?, ?)`, peerID, p, formatTime(now)); err != nil {
			return nil, nil, fmt.Errorf("store: advertise route %s of %s: %w", p, peerID, err)
		}
		added = append(added, p)
	}
	return added, removed, nil
}

// SetApproved approves or revokes one advertised prefix. ErrNotFound
// when the peer does not advertise it.
func (r *Routes) SetApproved(ctx context.Context, peerID, prefix, by string, approved bool, now time.Time) error {
	var res interface{ RowsAffected() (int64, error) }
	var err error
	if approved {
		res, err = r.q.ExecContext(ctx, `UPDATE peer_routes SET approved_at = ?, approved_by = ? WHERE peer_id = ? AND prefix = ?`, formatTime(now), by, peerID, prefix)
	} else {
		res, err = r.q.ExecContext(ctx, `UPDATE peer_routes SET approved_at = NULL, approved_by = NULL WHERE peer_id = ? AND prefix = ?`, peerID, prefix)
	}
	if err != nil {
		return fmt.Errorf("store: set route %s of %s approved=%v: %w", prefix, peerID, approved, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListPeer returns a peer's advertised prefixes, ordered by prefix.
func (r *Routes) ListPeer(ctx context.Context, peerID string) ([]PeerRoute, error) {
	return r.list(ctx, `SELECT peer_id, prefix, advertised_at, approved_at, approved_by FROM peer_routes WHERE peer_id = ? ORDER BY prefix`, peerID)
}

// ListAll returns every advertised prefix, ordered by peer id then prefix.
func (r *Routes) ListAll(ctx context.Context) ([]PeerRoute, error) {
	return r.list(ctx, `SELECT peer_id, prefix, advertised_at, approved_at, approved_by FROM peer_routes ORDER BY peer_id, prefix`)
}

func (r *Routes) list(ctx context.Context, query string, args ...any) ([]PeerRoute, error) {
	rows, err := r.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list routes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []PeerRoute
	for rows.Next() {
		var (
			pr         PeerRoute
			advertised string
			approvedAt *string
			approvedBy *string
		)
		if err := rows.Scan(&pr.PeerID, &pr.Prefix, &advertised, &approvedAt, &approvedBy); err != nil {
			return nil, fmt.Errorf("store: scan route: %w", err)
		}
		pr.AdvertisedAt = parseTime(advertised)
		if approvedAt != nil {
			pr.Approved = true
			pr.ApprovedAt = parseTime(*approvedAt)
		}
		if approvedBy != nil {
			pr.ApprovedBy = *approvedBy
		}
		out = append(out, pr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list routes: %w", err)
	}
	return out, nil
}
