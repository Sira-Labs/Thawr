package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Token is a one-time enrollment token. The secret itself is never
// stored; SecretHash is its SHA-256 in hex.
type Token struct {
	ID           string
	SecretHash   string
	OwnerID      string
	Kind         string
	Tags         []string
	PeerName     string
	CreatedBy    string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	UsedAt       *time.Time
	UsedByPeerID string
	// IssuedByAdmin records that an admin created the token, which lets
	// it take a peer name the policy selects.
	IssuedByAdmin bool
}

// Tokens accesses the enrollment_tokens table.
type Tokens struct {
	q querier
}

//nolint:gosec // a column list, not a credential
const tokenColumns = `id, secret_hash, owner_id, kind, tags, peer_name, created_by, created_at, expires_at, used_at, used_by_peer_id, issued_by_admin`

func scanToken(row interface{ Scan(...any) error }) (Token, error) {
	var (
		t                          Token
		tags, created, expires     string
		peerName, usedAt, usedByID sql.NullString
	)
	if err := row.Scan(&t.ID, &t.SecretHash, &t.OwnerID, &t.Kind, &tags, &peerName, &t.CreatedBy, &created, &expires, &usedAt, &usedByID, &t.IssuedByAdmin); err != nil {
		return Token{}, err
	}
	if err := json.Unmarshal([]byte(tags), &t.Tags); err != nil {
		return Token{}, fmt.Errorf("token %s tags: %w", t.ID, err)
	}
	t.PeerName = peerName.String
	t.CreatedAt = parseTime(created)
	t.ExpiresAt = parseTime(expires)
	t.UsedAt = parseTimePtr(usedAt)
	t.UsedByPeerID = usedByID.String
	return t, nil
}

// Create inserts t.
func (s *Tokens) Create(ctx context.Context, t Token) error {
	tags, err := json.Marshal(nonNil(t.Tags))
	if err != nil {
		return fmt.Errorf("store: encode tags: %w", err)
	}
	_, err = s.q.ExecContext(ctx,
		`INSERT INTO enrollment_tokens (`+tokenColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)`,
		t.ID, t.SecretHash, t.OwnerID, t.Kind, string(tags), nullString(t.PeerName), t.CreatedBy,
		formatTime(t.CreatedAt), formatTime(t.ExpiresAt), t.IssuedByAdmin)
	if isUniqueViolation(err) {
		return fmt.Errorf("token %s: %w", t.ID, ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("store: create token %s: %w", t.ID, err)
	}
	return nil
}

// GetByHash returns the token with the given secret hash or ErrNotFound.
func (s *Tokens) GetByHash(ctx context.Context, hash string) (Token, error) {
	t, err := scanToken(s.q.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM enrollment_tokens WHERE secret_hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	if err != nil {
		return Token{}, fmt.Errorf("store: get token by hash: %w", err)
	}
	return t, nil
}

// MarkUsed records the use of token id by peerID. It succeeds only when
// the token was unused, so concurrent enrollments cannot both win.
func (s *Tokens) MarkUsed(ctx context.Context, id, peerID string, now time.Time) error {
	res, err := s.q.ExecContext(ctx,
		`UPDATE enrollment_tokens SET used_at = ?, used_by_peer_id = ? WHERE id = ? AND used_at IS NULL`,
		formatTime(now), peerID, id)
	if err != nil {
		return fmt.Errorf("store: mark token %s used: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: mark token %s used: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("token %s already used: %w", id, ErrConflict)
	}
	return nil
}

// List returns all tokens, newest first.
func (s *Tokens) List(ctx context.Context) ([]Token, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+tokenColumns+` FROM enrollment_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan token: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list tokens: %w", err)
	}
	return out, nil
}

// Delete removes the token or returns ErrNotFound.
func (s *Tokens) Delete(ctx context.Context, id string) error {
	res, err := s.q.ExecContext(ctx, `DELETE FROM enrollment_tokens WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete token %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("token %s: %w", id, ErrNotFound)
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
