package control

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/thedatadudech/thawr/internal/store"
)

// auditEnv is the enrol env with an auditor on every service.
func auditEnv(t *testing.T) *enrollEnv {
	t.Helper()
	env := newEnrollEnv(t, "100.64.0.0/10")
	a := NewAuditor(env.clk.Now)
	env.users.WithAuditor(a)
	env.tokens.WithAuditor(a)
	env.enroller.WithAuditor(a)
	env.registry.WithAuditor(a)
	return env
}

// lastAudit returns the newest entry with the action, failing when none.
func lastAudit(t *testing.T, st *store.Store, action string) store.AuditEntry {
	t.Helper()
	got, err := st.Audit().List(context.Background(), store.AuditQuery{Action: action, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("no audit entry for %s", action)
	}
	return got[0]
}

func TestAuditEveryMutation(t *testing.T) {
	env := auditEnv(t)
	ctx := context.Background()
	alice := asPrincipal(mustUser(t, env.users, "alice", store.RoleMember))
	if e := lastAudit(t, env.st, AuditUserCreate); e.Actor != "local" || e.ActorRole != store.RoleAdmin || e.Target != alice.UserID || e.Details["name"] != "alice" || e.Details["role"] != "member" {
		t.Errorf("user.create: %+v", e)
	}

	created, err := env.tokens.Create(ctx, env.admin, TokenRequest{OwnerName: "alice", Kind: "server", Tags: []string{"tag:nas"}})
	if err != nil {
		t.Fatal(err)
	}
	if e := lastAudit(t, env.st, AuditTokenCreate); e.Actor != "markus" || e.ActorRole != store.RoleAdmin || e.Target != created.Token.ID || e.Details["owner"] != "alice" || e.Details["kind"] != "server" || e.Details["tags"] != "tag:nas" || e.Details["expires_at"] == "" {
		t.Errorf("token.create: %+v", e)
	}
	for k, v := range lastAudit(t, env.st, AuditTokenCreate).Details {
		if v == created.Secret {
			t.Errorf("token secret in audit details under %s", k)
		}
	}

	res, err := env.enroll(t, created.Secret, "nas")
	if err != nil {
		t.Fatal(err)
	}
	if e := lastAudit(t, env.st, AuditPeerEnrol); e.Actor != "peer:nas" || e.ActorRole != RolePeer || e.Target != res.Peer.ID || e.Details["token"] != created.Token.ID || e.Details["kind"] != "server" || len(e.Details["key"]) != 8 || e.Details["os"] != "linux/amd64" {
		t.Errorf("peer.enrol: %+v", e)
	}

	if err := env.registry.Rename(ctx, env.admin, "nas", "nas2"); err != nil {
		t.Fatal(err)
	}
	if e := lastAudit(t, env.st, AuditPeerRename); e.Actor != "markus" || e.Target != res.Peer.ID || e.Details["from"] != "nas" || e.Details["to"] != "nas2" {
		t.Errorf("peer.rename: %+v", e)
	}

	gen, err := env.registry.RotateKey(ctx, res.Peer.ID, newPubKey(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if e := lastAudit(t, env.st, AuditPeerRotateKey); e.Actor != "peer:nas2" || e.ActorRole != RolePeer || e.Target != res.Peer.ID || len(e.Details["key"]) != 8 || e.Details["generation"] == "" || e.Details["generation"] != strconv.FormatInt(gen, 10) {
		t.Errorf("peer.rotate_key: %+v", e)
	}

	tok2, _ := env.tokens.Create(ctx, alice, TokenRequest{OwnerName: "alice", Kind: "human"})
	if err := env.tokens.Revoke(ctx, alice, tok2.Token.ID); err != nil {
		t.Fatal(err)
	}
	if e := lastAudit(t, env.st, AuditTokenRevoke); e.Actor != "alice" || e.ActorRole != store.RoleMember || e.Target != tok2.Token.ID {
		t.Errorf("token.revoke: %+v", e)
	}

	static, err := env.registry.CreateStatic(ctx, LocalAdmin, StaticRequest{OwnerName: "alice", Name: "alice-phone"})
	if err != nil {
		t.Fatal(err)
	}
	if e := lastAudit(t, env.st, AuditPeerCreateStatic); e.Actor != "local" || e.ActorRole != store.RoleAdmin || e.Target != static.Peer.ID || e.Details["owner"] != "alice" || e.Details["name"] != "alice-phone" || len(e.Details["key"]) != 8 {
		t.Errorf("peer.create_static: %+v", e)
	}
	if e := lastAudit(t, env.st, AuditPeerCreateStatic); e.Details["key"] == static.Peer.PublicKey {
		t.Error("full public key in details (fingerprint expected)")
	}

	if err := env.registry.Leave(ctx, res.Peer.ID); err != nil {
		t.Fatal(err)
	}
	if e := lastAudit(t, env.st, AuditPeerLeave); e.Actor != "peer:nas2" || e.Target != res.Peer.ID || e.Details["name"] != "nas2" {
		t.Errorf("peer.leave: %+v", e)
	}
	if err := env.registry.Delete(ctx, env.admin, "alice-phone"); err != nil {
		t.Fatal(err)
	}
	if e := lastAudit(t, env.st, AuditPeerDelete); e.Actor != "markus" || e.Target != static.Peer.ID || e.Details["name"] != "alice-phone" {
		t.Errorf("peer.delete: %+v", e)
	}

	if _, err := env.users.Authenticate(ctx, "alice", "wrong password here"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wrong password: %v", err)
	}
	if e := lastAudit(t, env.st, AuditLoginFailed); e.Actor != "alice" || e.ActorRole != RoleAnonymous || e.Target != "alice" {
		t.Errorf("login.failed: %+v", e)
	}
	if _, err := env.users.Authenticate(ctx, "nobody", "wrong password here"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unknown user: %v", err)
	}
	if e := lastAudit(t, env.st, AuditLoginFailed); e.Actor != "nobody" {
		t.Errorf("login.failed unknown user: %+v", e)
	}
	if _, err := env.users.Authenticate(ctx, "alice", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if e := lastAudit(t, env.st, AuditLoginOK); e.Actor != "alice" || e.ActorRole != store.RoleMember {
		t.Errorf("login.ok: %+v", e)
	}

	path := filepath.Join(t.TempDir(), "policy.yaml")
	write(t, path, "version: 1\nacls: []\n")
	svc := NewPolicyService(env.st, quietLogger(), path, nil).WithAuditor(NewAuditor(env.clk.Now))
	if err := svc.LoadInitial(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Reload(ctx, env.admin); err != nil {
		t.Fatal(err)
	}
	if e := lastAudit(t, env.st, AuditPolicyReload); e.Actor != "markus" || e.Target != path || e.Details["rules"] != "0" || e.Details["hash"] == "" {
		t.Errorf("policy.reload: %+v", e)
	}

	all, _ := env.st.Audit().List(ctx, store.AuditQuery{})
	for _, e := range all {
		if !e.At.Equal(env.clk.Now()) {
			t.Errorf("entry %s not stamped with the injected clock: %v", e.Action, e.At)
		}
	}
}

// TestAuditFailureRollsBack: when the audit row cannot be written the
// mutation does not happen either.
func TestAuditFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "t.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clk := newClock()
	a := NewAuditor(clk.Now)
	users, err := NewUsers(st, clk.Now, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	env := &enrollEnv{st: st, clk: clk, users: users, tokens: NewTokens(st, clk.Now, quietLogger()).WithAuditor(a),
		enroller: NewEnroller(st, clk.Now, quietLogger(), netipPrefix("100.64.0.0/10"), "").WithAuditor(a),
		registry: NewRegistry(st, quietLogger()).WithAuditor(a)}
	env.admin = asPrincipal(mustUser(t, users, "markus", store.RoleAdmin))
	res, err := env.enroll(t, env.token(t, TokenRequest{}), "nas")
	if err != nil {
		t.Fatal(err)
	}
	// A second connection removes the table under the running services.
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.ExecContext(ctx, `DROP TABLE audit_log`); err != nil {
		t.Fatal(err)
	}
	if err := env.registry.Rename(ctx, env.admin, "nas", "nas2"); err == nil {
		t.Fatal("rename succeeded without an audit row")
	}
	p, err := env.st.Peers().GetByID(ctx, res.Peer.ID)
	if err != nil || p.Name != "nas" {
		t.Errorf("rename applied despite audit failure: %+v %v", p, err)
	}
}

// TestNilAuditorRecordsNothing keeps services usable without an auditor.
func TestNilAuditorRecordsNothing(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	if _, err := env.enroll(t, env.token(t, TokenRequest{}), "nas"); err != nil {
		t.Fatal(err)
	}
	got, _ := env.st.Audit().List(context.Background(), store.AuditQuery{})
	if len(got) != 0 {
		t.Errorf("entries without an auditor: %+v", got)
	}
	var a *Auditor
	if err := a.Record(context.Background(), env.st, LocalAdmin, "x", "", nil); err != nil {
		t.Error(err)
	}
}

func netipPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// TestPolicyReloadAuditFailureKeepsOldPolicy: when the audit row cannot
// be written the reload fails and the previous policy stays in force,
// with the generation unchanged.
func TestPolicyReloadAuditFailureKeepsOldPolicy(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "t.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	write(t, policyPath, "version: 1\nacls:\n  - action: accept\n    src: ['*']\n    dst: ['*:*']\n")
	svc := NewPolicyService(st, quietLogger(), policyPath, nil).WithAuditor(NewAuditor(newClock().Now))
	if err := svc.LoadInitial(ctx); err != nil {
		t.Fatal(err)
	}
	before := svc.Current().Hash
	gen0, _ := st.Meta().Generation(ctx)

	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.ExecContext(ctx, `DROP TABLE audit_log`); err != nil {
		t.Fatal(err)
	}
	write(t, policyPath, "version: 1\nacls: []\n")
	if _, err := svc.Reload(ctx, LocalAdmin); err == nil {
		t.Fatal("reload succeeded without an audit table")
	}
	if svc.Current().Hash != before || len(svc.Current().ACLs) != 1 {
		t.Errorf("new policy published despite the failed transaction: %+v", svc.Current())
	}
	if gen, _ := st.Meta().Generation(ctx); gen != gen0 {
		t.Errorf("generation advanced on a failed reload: %d -> %d", gen0, gen)
	}
}

// TestPolicyReloadConcurrent: parallel reloads are serialised; every one
// commits its generation bump and audit row.
func TestPolicyReloadConcurrent(t *testing.T) {
	env := auditEnv(t)
	ctx := context.Background()
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	write(t, policyPath, "version: 1\nacls:\n  - action: accept\n    src: ['*']\n    dst: ['*:*']\n")
	notify := &policyNotifier{}
	svc := NewPolicyService(env.st, quietLogger(), policyPath, notify).WithAuditor(NewAuditor(env.clk.Now))
	if err := svc.LoadInitial(ctx); err != nil {
		t.Fatal(err)
	}
	gen0, _ := env.st.Meta().Generation(ctx)
	const n = 8
	errs := make(chan error, n)
	for range n {
		go func() {
			_, err := svc.Reload(ctx, env.admin)
			errs <- err
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Errorf("reload: %v", err)
		}
	}
	if gen, _ := env.st.Meta().Generation(ctx); gen != gen0+n {
		t.Errorf("generation: %d, want %d", gen, gen0+n)
	}
	rows, err := env.st.Audit().List(ctx, store.AuditQuery{Action: AuditPolicyReload})
	if err != nil || len(rows) != n || rows[0].Actor != "markus" {
		t.Errorf("audit rows: %d %v", len(rows), err)
	}
	if notify.n != n {
		t.Errorf("notifications: %d, want %d", notify.n, n)
	}
}
