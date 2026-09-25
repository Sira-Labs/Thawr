package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
)

// restEnv wires the REST handler to real control services on a temp DB.
type restEnv struct {
	t        *testing.T
	st       *store.Store
	users    *control.Users
	tokens   *control.Tokens
	registry *control.Registry
	sessions *Sessions
	paths    *control.PathTable
	handler  http.Handler // HTTPS-style handler with sessions
	local    http.Handler // admin-socket-style handler
}

func newRESTEnv(t *testing.T, mods ...func(*RESTDeps, *restEnv)) *restEnv {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now
	users, err := control.NewUsers(st, now, quiet)
	if err != nil {
		t.Fatal(err)
	}
	env := &restEnv{t: t, st: st, users: users,
		tokens:   control.NewTokens(st, now, quiet),
		registry: control.NewRegistry(st, quiet).WithOverlay(netip.MustParsePrefix("100.64.0.0/10")),
		sessions: NewSessions(now),
		paths:    control.NewPathTable(now),
	}
	ui := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("Thawr")}}
	deps := RESTDeps{Status: fakeStatus{}, UI: ui, Logger: quiet, Users: users, Auth: users, Tokens: env.tokens,
		Peers: env.registry, Paths: env.paths, Sessions: env.sessions, Join: JoinInfo{ServerURL: "https://vpn.example.com", Fingerprint: "sha256:ab"},
		Hub: HubInfo{PublicKey: "HUBPUBKEY=", Endpoint: "vpn.example.com:51820", Overlay: netip.MustParsePrefix("100.64.0.0/10")}}
	for _, m := range mods {
		m(&deps, env)
	}
	env.handler, err = NewREST(deps)
	if err != nil {
		t.Fatal(err)
	}
	deps.Local = true
	deps.Sessions = nil
	env.local, err = NewREST(deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.Create(ctx, control.LocalAdmin, "markus", store.RoleAdmin, "adminpassword"); err != nil {
		t.Fatal(err)
	}
	if _, err := users.Create(ctx, control.LocalAdmin, "alice", store.RoleMember, "alicepassword"); err != nil {
		t.Fatal(err)
	}
	return env
}

type session struct {
	cookies []*http.Cookie
	csrf    string
}

func (e *restEnv) login(name, password string) (*httptest.ResponseRecorder, session) {
	body, _ := json.Marshal(map[string]string{"name": name, "password": password})
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/login", bytes.NewReader(body))
	e.handler.ServeHTTP(rec, req)
	var s session
	s.cookies = rec.Result().Cookies()
	var me meView
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	s.csrf = me.CSRF
	return rec, s
}

func (e *restEnv) do(h http.Handler, s session, method, path string, body any, withCSRF bool) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequestWithContext(context.Background(), method, path, r)
	for _, c := range s.cookies {
		req.AddCookie(c)
	}
	if withCSRF {
		req.Header.Set(CSRFHeader, s.csrf)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// mustPeerID looks a peer up by name as the local admin.
func mustPeerID(t *testing.T, env *restEnv, name string) string {
	t.Helper()
	p, err := env.registry.Get(context.Background(), control.LocalAdmin, name)
	if err != nil {
		t.Fatal(err)
	}
	return p.ID
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}

func TestRESTAuth(t *testing.T) {
	env := newRESTEnv(t)
	if rec := env.do(env.handler, session{}, http.MethodGet, "/api/v1/peers", nil, false); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d", rec.Code)
	}
	if rec, _ := env.login("markus", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", rec.Code)
	}
	rec, admin := env.login("markus", "adminpassword")
	if rec.Code != http.StatusOK || admin.csrf == "" || len(admin.cookies) != 1 {
		t.Fatalf("login: %d cookies=%d body=%s", rec.Code, len(admin.cookies), rec.Body.String())
	}
	if c := admin.cookies[0]; c.Name != SessionCookie || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie attributes: %+v", c)
	}
	if strings.Contains(rec.Body.String(), "argon2") {
		t.Error("login response leaks the password hash")
	}
	if rec := env.do(env.handler, admin, http.MethodGet, "/api/v1/peers", nil, false); rec.Code != http.StatusOK {
		t.Errorf("GET with session: %d", rec.Code)
	}
	body := map[string]any{"owner": "markus", "kind": "human"}
	if rec := env.do(env.handler, admin, http.MethodPost, "/api/v1/tokens", body, false); rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF: %d", rec.Code)
	}
	if rec := env.do(env.handler, admin, http.MethodPost, "/api/v1/tokens", body, true); rec.Code != http.StatusCreated {
		t.Errorf("POST with CSRF: %d %s", rec.Code, rec.Body.String())
	}
	if rec := env.do(env.handler, admin, http.MethodGet, "/api/v1/me", nil, false); !strings.Contains(rec.Body.String(), `"role":"admin"`) || !strings.Contains(rec.Body.String(), admin.csrf) {
		t.Errorf("me: %s", rec.Body.String())
	}

	_, member := env.login("alice", "alicepassword")
	if rec := env.do(env.handler, member, http.MethodGet, "/api/v1/users", nil, false); rec.Code != http.StatusForbidden {
		t.Errorf("member listing users: %d", rec.Code)
	}
	if rec := env.do(env.handler, member, http.MethodPost, "/api/v1/tokens", map[string]any{"owner": "markus", "kind": "human"}, true); rec.Code != http.StatusForbidden {
		t.Errorf("member token for other owner: %d", rec.Code)
	}

	if rec := env.do(env.handler, admin, http.MethodPost, "/api/v1/logout", nil, false); rec.Code != http.StatusNoContent {
		t.Errorf("logout: %d", rec.Code)
	}
	if rec := env.do(env.handler, admin, http.MethodGet, "/api/v1/peers", nil, false); rec.Code != http.StatusUnauthorized {
		t.Errorf("after logout: %d", rec.Code)
	}

	// The admin socket needs no login and no CSRF.
	if rec := env.do(env.local, session{}, http.MethodPost, "/api/v1/tokens", body, false); rec.Code != http.StatusCreated {
		t.Errorf("local socket create token: %d %s", rec.Code, rec.Body.String())
	}
	if rec := env.do(env.local, session{}, http.MethodPost, "/api/v1/login", map[string]string{"name": "x", "password": "y"}, false); rec.Code != http.StatusNotFound {
		t.Errorf("login on socket: %d", rec.Code)
	}
}

func TestLoginRateLimitHTTP(t *testing.T) {
	env := newRESTEnv(t)
	var last int
	for i := 0; i < 12; i++ {
		rec, _ := env.login("markus", "wrong")
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("after 12 failures: %d, want 429", last)
	}
}

func TestTokenCreateShowsJoinCommandOnce(t *testing.T) {
	env := newRESTEnv(t)
	rec := env.do(env.local, session{}, http.MethodPost, "/api/v1/tokens",
		map[string]any{"owner": "alice", "kind": "server", "tags": []string{"tag:prod"}, "expires": "2h", "peer_name": "nas"}, false)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created createdTokenView
	decode(t, rec, &created)
	if !strings.HasPrefix(created.Secret, control.TokenPrefix) || created.Owner != "alice" || created.Kind != "server" || created.PeerName != "nas" {
		t.Errorf("created view: %+v", created)
	}
	want := "thawr client up --server https://vpn.example.com --token " + created.Secret + " --fingerprint sha256:ab"
	if created.JoinCommand != want {
		t.Errorf("join command %q, want %q", created.JoinCommand, want)
	}
	exp, _ := time.Parse(time.RFC3339, created.ExpiresAt)
	if d := time.Until(exp); d < 119*time.Minute || d > 121*time.Minute {
		t.Errorf("expiry %s not about 2h away", created.ExpiresAt)
	}
	list := env.do(env.local, session{}, http.MethodGet, "/api/v1/tokens", nil, false)
	if strings.Contains(list.Body.String(), created.Secret) || strings.Contains(list.Body.String(), "join_command") {
		t.Error("token list leaks the secret")
	}
	var tokens []tokenView
	decode(t, list, &tokens)
	if len(tokens) != 1 || tokens[0].ID != created.ID {
		t.Errorf("list: %+v", tokens)
	}
	if rec := env.do(env.local, session{}, http.MethodDelete, "/api/v1/tokens/"+created.ID, nil, false); rec.Code != http.StatusNoContent {
		t.Errorf("revoke: %d", rec.Code)
	}
	if rec := env.do(env.local, session{}, http.MethodDelete, "/api/v1/tokens/"+created.ID, nil, false); rec.Code != http.StatusNotFound {
		t.Errorf("revoke twice: %d", rec.Code)
	}
	for _, bad := range []map[string]any{{"owner": "alice", "kind": "robot"}, {"owner": "ghost", "kind": "human"}, {"owner": "alice", "kind": "human", "expires": "soon"}, {"owner": "alice", "kind": "human", "bogus": 1}} {
		if rec := env.do(env.local, session{}, http.MethodPost, "/api/v1/tokens", bad, false); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", bad, rec.Code)
		}
	}
}

// enrolPeer enrols "<owner>-box" for owner and returns the peer.
func enrolPeer(t *testing.T, env *restEnv, owner string) store.Peer {
	t.Helper()
	ctx := context.Background()
	enroller := control.NewEnroller(env.st, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)), netip.MustParsePrefix("100.64.0.0/10"), "")
	c, err := env.tokens.Create(ctx, control.LocalAdmin, control.TokenRequest{OwnerName: owner, Kind: "human"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := enroller.Enroll(ctx, control.EnrollRequest{Token: c.Secret, PublicKey: newKey(t), Hostname: owner + "-box", OS: "linux", Arch: "amd64", ClientVersion: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	return res.Peer
}

func TestPeersCRUD(t *testing.T) {
	env := newRESTEnv(t)
	for _, owner := range []string{"alice", "markus"} {
		enrolPeer(t, env, owner)
	}
	var peers []peerView
	decode(t, env.do(env.local, session{}, http.MethodGet, "/api/v1/peers", nil, false), &peers)
	if len(peers) != 2 || peers[0].Owner != "alice" || peers[0].IPv4 == "" || peers[0].Version != "0.1.0" || peers[0].OS != "linux/amd64" {
		t.Errorf("list: %+v", peers)
	}
	_, member := env.login("alice", "alicepassword")
	decode(t, env.do(env.handler, member, http.MethodGet, "/api/v1/peers", nil, false), &peers)
	if len(peers) != 1 || peers[0].Name != "alice-box" {
		t.Errorf("member list: %+v", peers)
	}
	if rec := env.do(env.handler, member, http.MethodPatch, "/api/v1/peers/alice-box", map[string]string{"name": "x"}, true); rec.Code != http.StatusForbidden {
		t.Errorf("member rename: %d", rec.Code)
	}
	rec := env.do(env.local, session{}, http.MethodPatch, "/api/v1/peers/alice-box", map[string]string{"name": "alice-laptop"}, false)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"alice-laptop"`) {
		t.Errorf("rename: %d %s", rec.Code, rec.Body.String())
	}
	if rec := env.do(env.local, session{}, http.MethodPatch, "/api/v1/peers/alice-laptop", map[string]string{"name": "markus-box"}, false); rec.Code != http.StatusBadRequest {
		t.Errorf("rename to taken: %d", rec.Code)
	}
	if rec := env.do(env.local, session{}, http.MethodGet, "/api/v1/peers/alice-laptop", nil, false); rec.Code != http.StatusOK {
		t.Errorf("get: %d", rec.Code)
	}
	// Paths reported by a peer appear in its detail, targets by name;
	// targets the caller may not see are left out.
	env.paths.Set(peers[0].ID, []control.PathState{{PeerID: "unknown", State: "direct"}, {PeerID: mustPeerID(t, env, "markus-box"), State: "direct", Endpoint: "203.0.113.9:4000"}})
	var detail peerDetail
	decode(t, env.do(env.local, session{}, http.MethodGet, "/api/v1/peers/alice-laptop", nil, false), &detail)
	if detail.Name != "alice-laptop" || len(detail.Paths) != 1 || detail.Paths[0].Peer != "markus-box" || detail.Paths[0].Endpoint != "203.0.113.9:4000" || detail.Paths[0].UpdatedAt == "" {
		t.Errorf("detail: %+v", detail)
	}
	// The summary counts every reported path, visible or not.
	if detail.PathSummary != (pathSummary{Direct: 2}) || len(detail.Endpoints) != 0 || len(detail.Filter) != 0 {
		t.Errorf("summary and empty extras: %+v", detail)
	}
	if rec := env.do(env.local, session{}, http.MethodDelete, "/api/v1/peers/alice-laptop", nil, false); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d", rec.Code)
	}
	if rec := env.do(env.local, session{}, http.MethodDelete, "/api/v1/peers/alice-laptop", nil, false); rec.Code != http.StatusNotFound {
		t.Errorf("delete twice: %d", rec.Code)
	}
	if rec := env.do(env.local, session{}, http.MethodGet, "/api/v1/users", nil, false); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "argon2") {
		t.Errorf("users list: %d %s", rec.Code, rec.Body.String())
	}
	if rec := env.do(env.local, session{}, http.MethodPost, "/api/v1/users", map[string]string{"name": "bob", "role": "member", "password": "bobpassword"}, false); rec.Code != http.StatusCreated {
		t.Errorf("create user: %d %s", rec.Code, rec.Body.String())
	}
	if rec := env.do(env.local, session{}, http.MethodPost, "/api/v1/users", map[string]string{"name": "bob", "role": "member", "password": "bobpassword"}, false); rec.Code != http.StatusConflict {
		t.Errorf("duplicate user: %d", rec.Code)
	}
}

func TestParseTTL(t *testing.T) {
	good := map[string]time.Duration{"": 0, "1h": time.Hour, "30m": 30 * time.Minute, "7d": 7 * 24 * time.Hour}
	for in, want := range good {
		if got, err := ParseTTL(in); err != nil || got != want {
			t.Errorf("ParseTTL(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"soon", "-1h", "0d", "1w"} {
		if _, err := ParseTTL(bad); err == nil {
			t.Errorf("ParseTTL(%q) accepted", bad)
		}
	}
}

func TestSessionsExpire(t *testing.T) {
	base := time.Now()
	now := base
	s := NewSessions(func() time.Time { return now })
	sess, err := s.Create("u1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(sess.Token); !ok {
		t.Fatal("fresh session missing")
	}
	now = base.Add(SessionTTL + time.Minute)
	if _, ok := s.Get(sess.Token); ok {
		t.Error("expired session still valid")
	}
}
