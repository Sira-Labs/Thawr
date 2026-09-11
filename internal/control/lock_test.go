package control

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"

	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/store"
	"github.com/thedatadudech/thawr/internal/wg"
)

type lockEnv struct {
	*enrollEnv
	svc    *LockService
	hubKey string
	pa, pb store.Peer
	ka, kb lock.PrivateKey
}

func newLockEnv(t *testing.T) *lockEnv {
	t.Helper()
	env := newEnrollEnv(t, "100.64.0.0/10")
	a := NewAuditor(env.clk.Now)
	env.registry.WithAuditor(a)
	hub, _ := wg.GenerateKey()
	svc := NewLockService(env.st, env.clk.Now, quietLogger(), hub.PublicKey().String()).WithAuditor(a)
	env.registry.WithLock(svc)
	pa, err := env.enroll(t, env.token(t, TokenRequest{}), "pa")
	if err != nil {
		t.Fatal(err)
	}
	pb, err := env.enroll(t, env.token(t, TokenRequest{}), "pb")
	if err != nil {
		t.Fatal(err)
	}
	ka, _ := lock.GenerateKey(rand.Reader)
	kb, _ := lock.GenerateKey(rand.Reader)
	return &lockEnv{enrollEnv: env, svc: svc, hubKey: hub.PublicKey().String(), pa: pa.Peer, pb: pb.Peer, ka: ka, kb: kb}
}

func signRecord(t *testing.T, k lock.PrivateKey, r lock.Record) lock.Signed {
	t.Helper()
	msg, err := r.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := lock.Sign(k, msg)
	if err != nil {
		t.Fatal(err)
	}
	return lock.Signed{Record: r, Signature: sig}
}

func signPeer(t *testing.T, k lock.PrivateKey, id, name, key string) lock.Signature {
	t.Helper()
	wk, err := wg.ParseKey(key)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := lock.PeerRecord{ID: id, Name: name, Key: [32]byte(wk)}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := lock.Sign(k, msg)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// enable installs the first record with pa as sole signer.
func (e *lockEnv) enable(t *testing.T) {
	t.Helper()
	rec := signRecord(t, e.ka, lock.Record{Generation: 1, Signers: []lock.Signer{{Key: e.ka.Public(), PeerID: e.pa.ID}}})
	if err := e.svc.Set(context.Background(), e.pa, rec); err != nil {
		t.Fatal(err)
	}
}

func TestLockSetAcceptsOnlySignedSuccessors(t *testing.T) {
	e := newLockEnv(t)
	ctx := context.Background()
	if cur, err := e.svc.Current(ctx); err != nil || cur != nil {
		t.Fatalf("before init: %+v %v", cur, err)
	}
	outsider, _ := lock.GenerateKey(rand.Reader)
	// The first record must be signed by one of its own keys.
	bad := signRecord(t, outsider, lock.Record{Generation: 1, Signers: []lock.Signer{{Key: e.ka.Public(), PeerID: e.pa.ID}}})
	if err := e.svc.Set(ctx, e.pa, bad); !errors.Is(err, ErrValidation) {
		t.Errorf("first record by outsider: %v", err)
	}
	e.enable(t)
	cur, err := e.svc.Current(ctx)
	if err != nil || cur == nil || cur.Record.Generation != 1 || !cur.Record.Enabled() {
		t.Fatalf("current: %+v %v", cur, err)
	}
	if e := lastAudit(t, e.st, AuditLockSet); e.Actor != "peer:pa" || e.Details["generation"] != "1" || e.Details["signers"] != "1" {
		t.Errorf("lock.set audit: %+v", e)
	}
	if ok, _ := e.svc.IsSigner(ctx, e.pa.ID); !ok {
		t.Error("pa not a signer")
	}
	if ok, _ := e.svc.IsSigner(ctx, e.pb.ID); ok {
		t.Error("pb is a signer")
	}
	// Replay, outsider and self-added signer are refused.
	replay := signRecord(t, e.ka, cur.Record)
	if err := e.svc.Set(ctx, e.pa, replay); !errors.Is(err, ErrValidation) {
		t.Errorf("replay: %v", err)
	}
	two := lock.Record{Generation: 2, Signers: []lock.Signer{{Key: e.ka.Public(), PeerID: e.pa.ID}, {Key: e.kb.Public(), PeerID: e.pb.ID}}}
	if err := e.svc.Set(ctx, e.pb, signRecord(t, e.kb, two)); !errors.Is(err, ErrValidation) {
		t.Errorf("self-added signer: %v", err)
	}
	if err := e.svc.Set(ctx, e.pa, signRecord(t, outsider, lock.Record{Generation: 9, Signers: []lock.Signer{{Key: outsider.Public(), PeerID: e.pa.ID}}})); !errors.Is(err, ErrValidation) {
		t.Errorf("hijack: %v", err)
	}
	if err := e.svc.Set(ctx, e.pa, signRecord(t, e.ka, two)); err != nil {
		t.Fatalf("add signer: %v", err)
	}
	if ok, _ := e.svc.IsSigner(ctx, e.pb.ID); !ok {
		t.Error("pb not a signer after being added")
	}
	// The new signer may disable the lock.
	if err := e.svc.Set(ctx, e.pb, signRecord(t, e.kb, lock.Record{Generation: 3, Disabled: true})); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if ok, _ := e.svc.IsSigner(ctx, e.pa.ID); ok {
		t.Error("signer after disable")
	}
	if cur, _ := e.svc.Current(ctx); cur == nil || cur.Record.Enabled() {
		t.Errorf("disabled record: %+v", cur)
	}
}

func TestSignPeerRequiresSigner(t *testing.T) {
	e := newLockEnv(t)
	ctx := context.Background()
	sigB := signPeer(t, e.ka, e.pb.ID, e.pb.Name, e.pb.PublicKey)
	if err := e.svc.Sign(ctx, e.pa, e.pb.ID, e.pb.PublicKey, e.ka.Public(), sigB); !errors.Is(err, ErrForbidden) {
		t.Errorf("sign before enable: %v", err)
	}
	e.enable(t)
	cases := []struct {
		name   string
		by     store.Peer
		peer   string
		key    string
		signer lock.PublicKey
		sig    lock.Signature
		want   error
	}{
		{"non-signer", e.pb, e.pa.ID, e.pa.PublicKey, e.kb.Public(), signPeer(t, e.kb, e.pa.ID, e.pa.Name, e.pa.PublicKey), ErrForbidden},
		{"signer with another key", e.pa, e.pb.ID, e.pb.PublicKey, e.kb.Public(), signPeer(t, e.kb, e.pb.ID, e.pb.Name, e.pb.PublicKey), ErrForbidden},
		{"stale key", e.pa, e.pb.ID, newPubKey(t), e.ka.Public(), sigB, ErrValidation},
		{"bad signature", e.pa, e.pb.ID, e.pb.PublicKey, e.ka.Public(), signPeer(t, e.ka, e.pb.ID, "other-name", e.pb.PublicKey), ErrValidation},
		{"unknown peer", e.pa, "nope", e.pb.PublicKey, e.ka.Public(), sigB, ErrNotFound},
	}
	for _, tc := range cases {
		if err := e.svc.Sign(ctx, tc.by, tc.peer, tc.key, tc.signer, tc.sig); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if err := e.svc.Sign(ctx, e.pa, e.pb.ID, e.pb.PublicKey, e.ka.Public(), sigB); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if a := lastAudit(t, e.st, AuditPeerSign); a.Actor != "peer:pa" || a.Target != e.pb.ID || a.Details["name"] != "pb" || len(a.Details["signer"]) != 8 || len(a.Details["key"]) != 8 {
		t.Errorf("peer.sign audit: %+v", a)
	}
	peers, hub, err := e.svc.ListPeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signed := map[string]bool{}
	for _, p := range peers {
		signed[p.Name] = p.Signed
	}
	if !signed["pb"] || signed["pa"] || hub.Signed || hub.ID != lock.HubID || hub.PublicKey != e.hubKey {
		t.Errorf("list: %+v hub=%+v", peers, hub)
	}
	if err := e.svc.Sign(ctx, e.pa, lock.HubID, e.hubKey, e.ka.Public(), signPeer(t, e.ka, lock.HubID, lock.HubID, e.hubKey)); err != nil {
		t.Fatalf("sign hub: %v", err)
	}
	if _, hub, _ = e.svc.ListPeers(ctx); !hub.Signed {
		t.Error("hub not signed")
	}
	e.svc.ReportKey(e.pb.ID, e.kb.Public().String())
	peers, _, _ = e.svc.ListPeers(ctx)
	for _, p := range peers {
		if p.Name == "pb" && p.LockKey != e.kb.Public().String() {
			t.Errorf("reported lock key missing: %+v", p)
		}
	}
	// Deleting the peer removes its signatures.
	if err := e.registry.Delete(ctx, e.admin, "pb"); err != nil {
		t.Fatal(err)
	}
	rows, _ := e.st.Signatures().ListAll(ctx)
	for _, r := range rows {
		if r.PeerID == e.pb.ID {
			t.Errorf("signature survived delete: %+v", r)
		}
	}
}

func TestRotateKeyStoresSignature(t *testing.T) {
	e := newLockEnv(t)
	ctx := context.Background()
	e.enable(t)
	newKey := newPubKey(t)
	// A non-signer cannot vouch for its own rotation.
	if _, err := e.registry.RotateKey(ctx, e.pb.ID, newKey, &SignedRotation{Signer: e.kb.Public(), Signature: signPeer(t, e.kb, e.pb.ID, "pb", newKey)}); !errors.Is(err, ErrForbidden) {
		t.Errorf("non-signer rotation: %v", err)
	}
	if p, _ := e.st.Peers().GetByID(ctx, e.pb.ID); p.PublicKey != e.pb.PublicKey {
		t.Error("key changed despite the refused signature")
	}
	// A bad signature by the signer is refused and nothing changes.
	if _, err := e.registry.RotateKey(ctx, e.pa.ID, newKey, &SignedRotation{Signer: e.ka.Public(), Signature: signPeer(t, e.ka, e.pa.ID, "wrong", newKey)}); !errors.Is(err, ErrValidation) {
		t.Errorf("bad rotation signature: %v", err)
	}
	if _, err := e.registry.RotateKey(ctx, e.pa.ID, newKey, &SignedRotation{Signer: e.ka.Public(), Signature: signPeer(t, e.ka, e.pa.ID, "pa", newKey)}); err != nil {
		t.Fatalf("signed rotation: %v", err)
	}
	b := NewNetMapBuilder(e.st, OwnerVisibility{}, nil, nil, HubConfig{PublicKey: e.hubKey, Overlay: netip.MustParsePrefix("100.64.0.0/10"), Address: netip.MustParseAddr("100.64.0.1")}, func() int64 { return 1 })
	nm, err := b.Build(ctx, e.pb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if nm.Lock == nil || nm.Lock.Record.Generation != 1 || len(nm.Peers) != 1 || nm.Peers[0].PublicKey != newKey || len(nm.Peers[0].Signatures) != 1 || nm.Peers[0].Signatures[0].Signer != e.ka.Public() {
		t.Errorf("netmap after signed rotation: lock=%+v peers=%+v", nm.Lock, nm.Peers)
	}
	if len(nm.Hub.Signatures) != 0 {
		t.Errorf("hub signed without a signature: %+v", nm.Hub)
	}
	// An unsigned rotation drops the peer to unsigned: old-key rows do not match.
	if _, err := e.registry.RotateKey(ctx, e.pa.ID, newPubKey(t), nil); err != nil {
		t.Fatal(err)
	}
	if nm, _ = b.Build(ctx, e.pb.ID); len(nm.Peers[0].Signatures) != 0 {
		t.Errorf("stale signature attached: %+v", nm.Peers[0].Signatures)
	}
	peers, _, _ := e.svc.ListPeers(ctx)
	for _, p := range peers {
		if p.Name == "pa" && p.Signed {
			t.Error("pa reported signed after an unsigned rotation")
		}
	}
	// Without a lock service, a signed rotation is a validation error.
	env := newEnrollEnv(t, "100.64.0.0/10")
	res, _ := env.enroll(t, env.token(t, TokenRequest{}), "solo")
	if _, err := env.registry.RotateKey(ctx, res.Peer.ID, newPubKey(t), &SignedRotation{}); !errors.Is(err, ErrValidation) {
		t.Errorf("signed rotation without lock service: %v", err)
	}
}
