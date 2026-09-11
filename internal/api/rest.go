package api

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"time"
)

// RESTDeps are the collaborators of the REST handler. Users, Tokens and
// Peers may be nil for a status-only handler (tests); then every
// management endpoint answers 503.
type RESTDeps struct {
	Status StatusSource
	// UI is the embedded admin UI root (index.html at the top).
	UI     fs.FS
	Logger *slog.Logger

	Users  UsersService
	Auth   Authenticator
	Tokens TokensService
	Peers  PeersService
	// Presence reports online peers; nil means unknown.
	Presence PresenceSource
	// Paths reports how each peer reaches the others; nil means unknown.
	Paths PathsSource
	// Endpoints reports each peer's candidate addresses; nil means unknown.
	Endpoints EndpointSource
	// NodeAuth and Relay enable GET /relay; without both it answers 501.
	NodeAuth NodeAuth
	Relay    RelaySession
	// Policy enables the policy endpoints.
	Policy PolicyService
	// Audit enables GET /api/v1/audit (admins only).
	Audit AuditService
	// Lock enables GET /api/v1/lock and the signed field of peer views.
	Lock LockView
	// Now is the clock for relative audit queries; defaults to time.Now.
	Now  func() time.Time
	Join JoinInfo
	// Hub is the server's WireGuard interface as phones connect to it.
	Hub HubInfo
	// Sessions backs cookie logins on the HTTPS listener.
	Sessions *Sessions
	// Local marks the admin-socket handler: every request acts as the
	// local admin and login is disabled.
	Local bool
}

type rest struct {
	deps RESTDeps
}

// NewREST returns the HTTP handler for the admin API, the embedded UI
// and the relay upgrade path. Build it once per listener.
func NewREST(deps RESTDeps) (http.Handler, error) {
	if deps.Status == nil {
		return nil, fmt.Errorf("api: StatusSource required")
	}
	if deps.UI == nil {
		return nil, fmt.Errorf("api: UI filesystem required")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	h := &rest{deps: deps}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		st, err := deps.Status.Status(r.Context())
		if err != nil {
			deps.Logger.Error("status", "err", err)
			writeError(w, http.StatusInternalServerError, "status unavailable")
			return
		}
		writeJSON(w, http.StatusOK, st)
	})
	if deps.Users != nil && deps.Tokens != nil && deps.Peers != nil {
		mux.HandleFunc("POST /api/v1/login", h.handleLogin)
		mux.HandleFunc("POST /api/v1/logout", h.handleLogout)
		mux.HandleFunc("GET /api/v1/me", h.requireAuth(h.handleMe))
		mux.HandleFunc("GET /api/v1/users", h.requireAdmin(h.handleListUsers))
		mux.HandleFunc("POST /api/v1/users", h.requireAdmin(h.handleCreateUser))
		mux.HandleFunc("GET /api/v1/tokens", h.requireAuth(h.handleListTokens))
		mux.HandleFunc("POST /api/v1/tokens", h.requireAuth(h.handleCreateToken))
		mux.HandleFunc("DELETE /api/v1/tokens/{id}", h.requireAuth(h.handleRevokeToken))
		mux.HandleFunc("GET /api/v1/peers", h.requireAuth(h.handleListPeers))
		mux.HandleFunc("POST /api/v1/peers/mobile", h.requireAuth(h.handleCreateMobile))
		mux.HandleFunc("GET /api/v1/peers/{name}", h.requireAuth(h.handleGetPeer))
		mux.HandleFunc("PATCH /api/v1/peers/{name}", h.requireAuth(h.handleRenamePeer))
		mux.HandleFunc("DELETE /api/v1/peers/{name}", h.requireAuth(h.handleDeletePeer))
		if deps.Policy != nil {
			mux.HandleFunc("GET /api/v1/policy", h.requireAuth(h.handleShowPolicy))
			mux.HandleFunc("POST /api/v1/policy/check", h.requireAdmin(h.handleCheckPolicy))
			mux.HandleFunc("POST /api/v1/policy/reload", h.requireAdmin(h.handleReloadPolicy))
		}
		if deps.Audit != nil {
			mux.HandleFunc("GET /api/v1/audit", h.requireAdmin(h.handleListAudit))
		}
		if deps.Lock != nil {
			mux.HandleFunc("GET /api/v1/lock", h.requireAuth(h.handleShowLock))
		}
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "unknown endpoint")
	})
	mux.HandleFunc("/relay", h.handleRelay)
	mux.Handle("/", http.FileServerFS(deps.UI))
	return mux, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
