package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sira-labs/thawr/internal/store"
)

// AuditService is what the audit endpoint needs from the store.
type AuditService interface {
	List(ctx context.Context, q store.AuditQuery) ([]store.AuditEntry, error)
}

// auditView is one audit entry as the REST API renders it.
type auditView struct {
	ID        int64             `json:"id"`
	At        time.Time         `json:"at"`
	Actor     string            `json:"actor"`
	ActorRole string            `json:"actor_role"`
	Action    string            `json:"action"`
	Target    string            `json:"target"`
	Details   map[string]string `json:"details"`
}

// handleListAudit answers GET /api/v1/audit for admins: newest first,
// filtered by since (RFC 3339 or a duration such as 24h), before_id,
// action, actor and limit.
func (h *rest) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q, err := parseAuditQuery(r, h.deps.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entries, err := h.deps.Audit.List(r.Context(), q)
	if err != nil {
		h.deps.Logger.Error("list audit", "err", err)
		writeError(w, http.StatusInternalServerError, "audit log unavailable")
		return
	}
	out := make([]auditView, 0, len(entries))
	for _, e := range entries {
		details := e.Details
		if details == nil {
			details = map[string]string{}
		}
		out = append(out, auditView{ID: e.ID, At: e.At, Actor: e.Actor, ActorRole: e.ActorRole, Action: e.Action, Target: e.Target, Details: details})
	}
	writeJSON(w, http.StatusOK, out)
}

// parseAuditQuery validates the query string of the audit endpoint.
func parseAuditQuery(r *http.Request, now time.Time) (store.AuditQuery, error) {
	var q store.AuditQuery
	v := r.URL.Query()
	if s := strings.TrimSpace(v.Get("since")); s != "" {
		since, err := parseSince(s, now)
		if err != nil {
			return q, err
		}
		q.Since = since
	}
	if s := v.Get("before_id"); s != "" {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil || id <= 0 {
			return q, &fieldError{"before_id", "must be a positive integer"}
		}
		q.BeforeID = id
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > store.MaxAuditLimit {
			return q, &fieldError{"limit", "must be 1-" + strconv.Itoa(store.MaxAuditLimit)}
		}
		q.Limit = n
	}
	q.Action = strings.TrimSpace(v.Get("action"))
	q.Actor = strings.TrimSpace(v.Get("actor"))
	return q, nil
}

// parseSince accepts an RFC 3339 time or a duration back from now.
func parseSince(s string, now time.Time) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return time.Time{}, &fieldError{"since", "must be an RFC 3339 time or a positive duration such as 24h"}
	}
	return now.Add(-d), nil
}

// fieldError names the query field a request got wrong.
type fieldError struct {
	field, msg string
}

func (e *fieldError) Error() string { return e.field + ": " + e.msg }
