package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
)

// RelaysService is what the REST layer needs from control.Relays
// (spec 016).
type RelaysService interface {
	CreateToken(ctx context.Context, by control.Principal, name string, ttl time.Duration) (control.CreatedRelayToken, error)
	List(ctx context.Context, by control.Principal) ([]control.RelayStatus, error)
	Delete(ctx context.Context, by control.Principal, name string) (store.Relay, error)
}

// relayView is one relay node as the admin API shows it. It carries no
// secret: the fingerprint is public, devices pin it.
type relayView struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	TLSFingerprint string `json:"tls_fingerprint"`
	Version        string `json:"version,omitempty"`
	Online         bool   `json:"online"`
	// Since is when the relay last went online or offline; empty when
	// it has not attached since the server started.
	Since        string `json:"since,omitempty"`
	RegisteredAt string `json:"registered_at"`
	LastSeenAt   string `json:"last_seen_at,omitempty"`
	Sessions     int    `json:"sessions"`
	Frames       uint64 `json:"frames"`
	Bytes        uint64 `json:"bytes"`
	Drops        uint64 `json:"drops"`
}

// createdRelayTokenView is returned exactly once; it is the only place
// the token's secret appears.
type createdRelayTokenView struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	ExpiresAt string `json:"expires_at"`
	Secret    string `json:"secret"`
}

func newRelayView(st control.RelayStatus) relayView {
	v := relayView{
		ID: st.Relay.ID, Name: st.Relay.Name, URL: st.Relay.URL, TLSFingerprint: st.Relay.TLSFingerprint, Version: st.Relay.Version,
		Online: st.Online, RegisteredAt: st.Relay.CreatedAt.UTC().Format(timeFormat),
		Sessions: st.Stats.Sessions, Frames: st.Stats.Frames, Bytes: st.Stats.Bytes, Drops: st.Stats.Drops,
	}
	if !st.Since.IsZero() {
		v.Since = st.Since.UTC().Format(timeFormat)
	}
	if st.Relay.LastSeenAt != nil {
		v.LastSeenAt = st.Relay.LastSeenAt.UTC().Format(timeFormat)
	}
	return v
}

func (h *rest) handleListRelays(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	relays, err := h.deps.Relays.List(r.Context(), p)
	if err != nil {
		h.writeControlError(w, err)
		return
	}
	out := make([]relayView, 0, len(relays))
	for _, st := range relays {
		out = append(out, newRelayView(st))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *rest) handleCreateRelayToken(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	var body struct {
		Name    string `json:"name"`
		Expires string `json:"expires"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ttl, err := ParseTTL(body.Expires)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.deps.Relays.CreateToken(r.Context(), p, body.Name, ttl)
	if err != nil {
		h.writeControlError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, createdRelayTokenView{
		ID: created.Token.ID, Name: created.Token.RelayName,
		ExpiresAt: created.Token.ExpiresAt.UTC().Format(timeFormat), Secret: created.Secret,
	})
}

// handleDeleteRelay removes the relay with the id in the path. The
// service deletes by name, so the id is resolved first; an id that
// matches nothing is a 404.
func (h *rest) handleDeleteRelay(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	id := r.PathValue("id")
	relays, err := h.deps.Relays.List(r.Context(), p)
	if err != nil {
		h.writeControlError(w, err)
		return
	}
	for _, st := range relays {
		if st.Relay.ID != id {
			continue
		}
		if _, err := h.deps.Relays.Delete(r.Context(), p, st.Relay.Name); err != nil {
			h.writeControlError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h.writeControlError(w, fmt.Errorf("relay %s: %w", id, control.ErrNotFound))
}
