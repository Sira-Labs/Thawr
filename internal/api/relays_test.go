package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/control"
)

const (
	restRelayURL = "https://relay-riyadh.example.com:443"
	restRelayFP  = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func newRelayRESTEnv(t *testing.T) (*restEnv, *control.Relays) {
	t.Helper()
	var relays *control.Relays
	env := newRESTEnv(t, func(d *RESTDeps, e *restEnv) {
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		relays = control.NewRelays(e.st, time.Now, quiet).WithAuditor(control.NewAuditor(time.Now))
		d.Relays = relays
	})
	return env, relays
}

// TestRESTRelays: token, list and delete over the admin API, the roles
// that may use them, and that no response but the token's own carries a
// secret.
func TestRESTRelays(t *testing.T) {
	env, relays := newRelayRESTEnv(t)
	ctx := context.Background()
	_, admin := env.login("markus", "adminpassword")
	_, member := env.login("alice", "alicepassword")

	// Roles: a member and an anonymous caller get nothing.
	for _, tc := range []struct {
		name         string
		s            session
		method, path string
		body         any
		want         int
	}{
		{"member lists", member, http.MethodGet, "/api/v1/relays", nil, http.StatusForbidden},
		{"member creates a token", member, http.MethodPost, "/api/v1/relays/tokens", map[string]string{}, http.StatusForbidden},
		{"member deletes", member, http.MethodDelete, "/api/v1/relays/rl_x", nil, http.StatusForbidden},
		{"anonymous lists", session{}, http.MethodGet, "/api/v1/relays", nil, http.StatusUnauthorized},
		{"anonymous creates a token", session{}, http.MethodPost, "/api/v1/relays/tokens", map[string]string{}, http.StatusUnauthorized},
	} {
		if rec := env.do(env.handler, tc.s, tc.method, tc.path, tc.body, true); rec.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, rec.Code, rec.Body, tc.want)
		}
	}
	// A session without the CSRF header may not create a token.
	if rec := env.do(env.handler, admin, http.MethodPost, "/api/v1/relays/tokens", map[string]string{}, false); rec.Code != http.StatusForbidden {
		t.Errorf("token without CSRF: %d %s", rec.Code, rec.Body)
	}

	// Empty list is [] rather than null.
	rec := env.do(env.handler, admin, http.MethodGet, "/api/v1/relays", nil, true)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list: %d %q", rec.Code, rec.Body)
	}

	// Token validation.
	for name, body := range map[string]map[string]string{
		"bad name":     {"name": "Not A Label"},
		"bad expiry":   {"expires": "soon"},
		"long expiry":  {"expires": "25h"},
		"unknown key":  {"label": "x"},
		"hub as name":  {"name": "hub"},
		"negative ttl": {"expires": "-1h"},
	} {
		if rec := env.do(env.handler, admin, http.MethodPost, "/api/v1/relays/tokens", body, true); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}

	rec = env.do(env.handler, admin, http.MethodPost, "/api/v1/relays/tokens", map[string]string{"name": "riyadh-1", "expires": "30m"}, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create token: %d %s", rec.Code, rec.Body)
	}
	var tok createdRelayTokenView
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Secret, control.RelayTokenPrefix) || !strings.HasPrefix(tok.ID, "rt_") || tok.Name != "riyadh-1" {
		t.Fatalf("token view: %+v", tok)
	}
	if exp, err := time.Parse(timeFormat, tok.ExpiresAt); err != nil || time.Until(exp) > 31*time.Minute || time.Until(exp) < 29*time.Minute {
		t.Errorf("expiry %q: %v", tok.ExpiresAt, err)
	}
	// The local admin on the socket may too, without a session.
	if rec := env.do(env.local, session{}, http.MethodPost, "/api/v1/relays/tokens", map[string]string{}, false); rec.Code != http.StatusCreated {
		t.Errorf("token over the admin socket: %d %s", rec.Code, rec.Body)
	}

	reg, err := relays.Register(ctx, control.RelayRegistration{Token: tok.Secret, URL: restRelayURL, Fingerprint: restRelayFP, Version: "0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relays.Attach(ctx, reg.Relay.ID, control.RelayHello{URL: restRelayURL, Fingerprint: restRelayFP, Version: "0.2.0"}); err != nil {
		t.Fatal(err)
	}
	if err := relays.Heartbeat(ctx, reg.Relay.ID, control.RelayStats{Sessions: 3, Frames: 10, Bytes: 4096, Drops: 1}); err != nil {
		t.Fatal(err)
	}

	rec = env.do(env.handler, admin, http.MethodGet, "/api/v1/relays", nil, true)
	var list []relayView
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != http.StatusOK || len(list) != 1 {
		t.Fatalf("list: %d %s %v", rec.Code, rec.Body, err)
	}
	got := list[0]
	if got.ID != reg.Relay.ID || got.Name != "riyadh-1" || got.URL != restRelayURL || got.TLSFingerprint != restRelayFP || got.Version != "0.2.0" ||
		!got.Online || got.Since == "" || got.RegisteredAt == "" || got.LastSeenAt == "" ||
		got.Sessions != 3 || got.Frames != 10 || got.Bytes != 4096 || got.Drops != 1 {
		t.Errorf("relay view: %+v", got)
	}
	// Neither the relay secret, nor its hash, nor the token appears.
	for _, secret := range []string{reg.Secret, reg.Relay.SecretHash, tok.Secret, "secret"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("list response carries %q: %s", secret, rec.Body)
		}
	}

	if rec := env.do(env.handler, admin, http.MethodDelete, "/api/v1/relays/rl_missing", nil, true); rec.Code != http.StatusNotFound {
		t.Errorf("delete of an unknown id: %d %s", rec.Code, rec.Body)
	}
	// The path takes the id, not the name.
	if rec := env.do(env.handler, admin, http.MethodDelete, "/api/v1/relays/riyadh-1", nil, true); rec.Code != http.StatusNotFound {
		t.Errorf("delete by name: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do(env.handler, admin, http.MethodDelete, "/api/v1/relays/"+reg.Relay.ID, nil, true); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do(env.handler, admin, http.MethodDelete, "/api/v1/relays/"+reg.Relay.ID, nil, true); rec.Code != http.StatusNotFound {
		t.Errorf("second delete: %d %s", rec.Code, rec.Body)
	}
	if _, err := relays.Authenticate(ctx, reg.Secret); err == nil {
		t.Error("the deleted relay's secret still authenticates")
	}
}

// TestRESTRelaysOff: without the service the routes do not exist.
func TestRESTRelaysOff(t *testing.T) {
	env := newRESTEnv(t)
	_, admin := env.login("markus", "adminpassword")
	if rec := env.do(env.handler, admin, http.MethodGet, "/api/v1/relays", nil, true); rec.Code != http.StatusNotFound {
		t.Errorf("list without the service: %d %s", rec.Code, rec.Body)
	}
}
