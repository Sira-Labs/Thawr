package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AuditEntry is one recorded control-plane mutation.
type AuditEntry struct {
	ID int64
	At time.Time
	// Actor is a user name, "local" for the admin socket, or
	// "peer:<name>"; ActorRole is admin, member, peer or anonymous.
	Actor     string
	ActorRole string
	// Action is dotted, e.g. peer.rename; Target is the id or name the
	// action applied to.
	Action  string
	Target  string
	Details map[string]string
}

// AuditQuery filters and pages List. Zero values mean no filter; Limit
// defaults to DefaultAuditLimit and is capped at MaxAuditLimit.
type AuditQuery struct {
	Since    time.Time
	BeforeID int64
	Action   string
	Actor    string
	Limit    int
}

// Audit page sizes.
const (
	DefaultAuditLimit = 100
	MaxAuditLimit     = 1000
)

// Audit accesses the audit_log table.
type Audit struct {
	q querier
}

// Append records e; ID and At (when zero) are assigned by the store.
func (a *Audit) Append(ctx context.Context, e AuditEntry) error {
	if e.Action == "" || e.Actor == "" {
		return fmt.Errorf("store: audit entry needs actor and action: %+v", e)
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	details := e.Details
	if details == nil {
		details = map[string]string{}
	}
	data, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("store: encode audit details: %w", err)
	}
	if _, err := a.q.ExecContext(ctx,
		`INSERT INTO audit_log (at, actor, actor_role, action, target, details) VALUES (?, ?, ?, ?, ?, ?)`,
		formatTime(e.At), e.Actor, e.ActorRole, e.Action, e.Target, string(data)); err != nil {
		return fmt.Errorf("store: append audit %s: %w", e.Action, err)
	}
	return nil
}

// List returns entries newest first, filtered by q.
func (a *Audit) List(ctx context.Context, q AuditQuery) ([]AuditEntry, error) {
	limit := q.Limit
	switch {
	case limit <= 0:
		limit = DefaultAuditLimit
	case limit > MaxAuditLimit:
		limit = MaxAuditLimit
	}
	var (
		where []string
		args  []any
	)
	if !q.Since.IsZero() {
		where = append(where, "at >= ?")
		args = append(args, formatTime(q.Since))
	}
	if q.BeforeID > 0 {
		where = append(where, "id < ?")
		args = append(args, q.BeforeID)
	}
	if q.Action != "" {
		where = append(where, "action = ?")
		args = append(args, q.Action)
	}
	if q.Actor != "" {
		where = append(where, "actor = ?")
		args = append(args, q.Actor)
	}
	query := `SELECT id, at, actor, actor_role, action, target, details FROM audit_log`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := a.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []AuditEntry{}
	for rows.Next() {
		var (
			e           AuditEntry
			at, details string
		)
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.ActorRole, &e.Action, &e.Target, &details); err != nil {
			return nil, fmt.Errorf("store: scan audit: %w", err)
		}
		e.At = parseTime(at)
		if err := json.Unmarshal([]byte(details), &e.Details); err != nil {
			return nil, fmt.Errorf("store: audit %d details: %w", e.ID, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	return out, nil
}

// Prune deletes entries recorded before the cut-off and returns how many.
func (a *Audit) Prune(ctx context.Context, before time.Time) (int64, error) {
	res, err := a.q.ExecContext(ctx, `DELETE FROM audit_log WHERE at < ?`, formatTime(before))
	if err != nil {
		return 0, fmt.Errorf("store: prune audit: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune audit: %w", err)
	}
	return n, nil
}

// Count is the number of rows in the audit log.
func (a *Audit) Count(ctx context.Context) (int64, error) {
	var n int64
	if err := a.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count audit rows: %w", err)
	}
	return n, nil
}
