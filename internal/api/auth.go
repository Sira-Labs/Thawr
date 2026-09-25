package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
)

// Cookie and header names of the admin UI session. The CSRF token is
// returned in the login and /me responses, never in a cookie, so the
// session cookie can stay HttpOnly.
const (
	SessionCookie = "thawr_session"
	CSRFHeader    = "X-CSRF-Token"
)

type ctxKey int

const principalKey ctxKey = 1

// principalFrom returns the principal attached by the auth middleware.
func principalFrom(ctx context.Context) (control.Principal, bool) {
	p, ok := ctx.Value(principalKey).(control.Principal)
	return p, ok
}

// requireAuth resolves the principal: the local admin on the socket, or
// a session cookie on the HTTPS listener. Mutating requests over a
// session must also carry the CSRF header matching the session.
func (h *rest) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.deps.Local {
			next(w, r.WithContext(context.WithValue(r.Context(), principalKey, control.LocalAdmin)))
			return
		}
		sess, ok := h.sessionFrom(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "login required")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get(CSRFHeader)), []byte(sess.CSRF)) != 1 {
				writeError(w, http.StatusForbidden, "missing or wrong CSRF token")
				return
			}
		}
		user, err := h.deps.Users.Get(r.Context(), sess.UserID)
		if err != nil || user.Disabled {
			h.deps.Sessions.Delete(sess.Token)
			writeError(w, http.StatusUnauthorized, "login required")
			return
		}
		p := control.Principal{UserID: user.ID, Name: user.Name, Role: user.Role}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	}
}

// requireAdmin wraps requireAuth and rejects non-admins.
func (h *rest) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		p, _ := principalFrom(r.Context())
		if !p.IsAdmin() {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		next(w, r)
	})
}

func (h *rest) sessionFrom(r *http.Request) (Session, bool) {
	if h.deps.Sessions == nil {
		return Session{}, false
	}
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return Session{}, false
	}
	return h.deps.Sessions.Get(c.Value)
}

func (h *rest) handleLogin(w http.ResponseWriter, r *http.Request) {
	if h.deps.Local || h.deps.Sessions == nil || h.deps.Auth == nil {
		writeError(w, http.StatusNotFound, "login is not available on this listener")
		return
	}
	var body struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := h.deps.Auth.Authenticate(r.Context(), body.Name, body.Password)
	if err != nil {
		switch {
		case errors.Is(err, control.ErrRateLimited):
			writeError(w, http.StatusTooManyRequests, "too many attempts, try again later")
		case errors.Is(err, control.ErrForbidden):
			writeError(w, http.StatusUnauthorized, "wrong name or password")
		default:
			h.deps.Logger.Error("login", "err", err)
			writeError(w, http.StatusInternalServerError, "login unavailable")
		}
		return
	}
	sess, err := h.deps.Sessions.Create(user.ID)
	if err != nil {
		h.deps.Logger.Error("session", "err", err)
		writeError(w, http.StatusInternalServerError, "login unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: sess.Token, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, Expires: sess.Expires})
	writeJSON(w, http.StatusOK, meView{Name: user.Name, Role: user.Role, CSRF: sess.CSRF})
}

func (h *rest) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := h.sessionFrom(r); ok {
		h.deps.Sessions.Delete(sess.Token)
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

// meView describes the caller; CSRF is what mutating requests must send
// in the X-CSRF-Token header (empty on the admin socket).
type meView struct {
	Name  string `json:"name"`
	Role  string `json:"role"`
	Local bool   `json:"local"`
	CSRF  string `json:"csrf,omitempty"`
}

func (h *rest) handleMe(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	view := meView{Name: p.Name, Role: p.Role, Local: p.Local}
	if sess, ok := h.sessionFrom(r); ok {
		view.CSRF = sess.CSRF
	}
	writeJSON(w, http.StatusOK, view)
}

// userView is the JSON shape of a user; the hash never leaves the server.
type userView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	CreatedAt string `json:"created_at"`
}

func newUserView(u store.User) userView {
	return userView{ID: u.ID, Name: u.Name, Role: u.Role, Disabled: u.Disabled, CreatedAt: u.CreatedAt.UTC().Format(timeFormat)}
}
