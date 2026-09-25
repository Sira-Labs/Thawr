package api

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
)

func TestAuditEndpoint(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	env := newRESTEnv(t, func(d *RESTDeps, e *restEnv) {
		d.Audit = e.st.Audit()
		d.Now = func() time.Time { return now }
		e.users.WithAuditor(control.NewAuditor(func() time.Time { return now }))
	})
	ctx := context.Background()
	// The env's users were created without an auditor; seed rows directly.
	seed := []store.AuditEntry{
		{At: now.Add(-48 * time.Hour), Actor: "markus", ActorRole: store.RoleAdmin, Action: control.AuditTokenCreate, Target: "tk_1", Details: map[string]string{"owner": "alice"}},
		{At: now.Add(-2 * time.Hour), Actor: "peer:nas", ActorRole: control.RolePeer, Action: control.AuditPeerRotateKey, Target: "p1"},
		{At: now.Add(-time.Hour), Actor: "alice", ActorRole: store.RoleMember, Action: control.AuditTokenRevoke, Target: "tk_2"},
	}
	for _, e := range seed {
		if err := env.st.Audit().Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	if rec := env.do(env.handler, session{}, http.MethodGet, "/api/v1/audit", nil, false); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rec.Code)
	}
	_, alice := env.login("alice", "alicepassword")
	if rec := env.do(env.handler, alice, http.MethodGet, "/api/v1/audit", nil, false); rec.Code != http.StatusForbidden {
		t.Errorf("member: %d %s", rec.Code, rec.Body.String())
	}
	_, admin := env.login("markus", "adminpassword")
	list := func(h http.Handler, s session, query string) ([]auditView, int) {
		rec := env.do(h, s, http.MethodGet, "/api/v1/audit"+query, nil, false)
		if rec.Code != http.StatusOK {
			return nil, rec.Code
		}
		var out []auditView
		decode(t, rec, &out)
		return out, rec.Code
	}
	all, code := list(env.handler, admin, "")
	// The env's users service carries an auditor, so the two users and
	// the two logins above are rows of their own next to the seeded ones.
	if code != http.StatusOK || len(all) < 7 || all[0].Action != control.AuditLoginOK {
		t.Fatalf("admin list: %d %+v", code, all)
	}
	if i := slices.IndexFunc(all, func(v auditView) bool { return v.Action == control.AuditTokenCreate }); i < 0 || all[i].Details["owner"] != "alice" {
		t.Errorf("seeded token.create row: %+v", all)
	}
	if got, _ := list(env.handler, admin, "?action=peer.rotate_key"); len(got) != 1 || got[0].Actor != "peer:nas" || got[0].ActorRole != control.RolePeer {
		t.Errorf("action filter: %+v", got)
	}
	if got, _ := list(env.handler, admin, "?actor=alice&action=token.revoke"); len(got) != 1 || got[0].Target != "tk_2" {
		t.Errorf("actor filter: %+v", got)
	}
	if got, _ := list(env.handler, admin, "?since=24h"); len(got) != len(all)-1 {
		t.Errorf("since duration: %d of %d", len(got), len(all))
	}
	if got, _ := list(env.handler, admin, "?since="+url.QueryEscape(now.Add(-90*time.Minute).Format(time.RFC3339))); len(got) != len(all)-2 {
		t.Errorf("since time: %d of %d", len(got), len(all))
	}
	if got, _ := list(env.handler, admin, "?limit=1"); len(got) != 1 || got[0].ID != all[0].ID {
		t.Errorf("limit: %+v", got)
	}
	if got, _ := list(env.handler, admin, "?before_id="+itoa(all[1].ID)); len(got) != len(all)-2 || got[0].ID != all[2].ID {
		t.Errorf("before_id: %+v", got)
	}
	for _, bad := range []string{"?since=yesterday", "?since=-5m", "?limit=0", "?limit=5000", "?before_id=x", "?before_id=-1"} {
		if _, code := list(env.handler, admin, bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, code)
		}
	}
	// A user created through the session listener is attributed to the
	// session's user, not to the admin socket. The principal comes from
	// the session cookie; no handler consults the request's TLS state,
	// which the real listener terminates before the handler.
	if rec := env.do(env.handler, admin, http.MethodPost, "/api/v1/users", map[string]string{"name": "bob", "role": "member", "password": "bobpassword1"}, true); rec.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := list(env.handler, admin, "?action=user.create&actor=markus"); len(got) != 1 || got[0].ActorRole != store.RoleAdmin || got[0].Details["name"] != "bob" {
		t.Errorf("user.create actor: %+v", got)
	}
	// The admin socket needs no session.
	if got, code := list(env.local, session{}, "?action=token.create"); code != http.StatusOK || len(got) != 1 {
		t.Errorf("local: %d %+v", code, got)
	}
	// Without the dependency the route does not exist.
	bare := newRESTEnv(t)
	_, bareAdmin := bare.login("markus", "adminpassword")
	if rec := bare.do(bare.handler, bareAdmin, http.MethodGet, "/api/v1/audit", nil, false); rec.Code != http.StatusNotFound {
		t.Errorf("without Audit dep: %d", rec.Code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
