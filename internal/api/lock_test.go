package api

import (
	"context"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	thawrv1 "github.com/thedatadudech/thawr/internal/api/proto/thawr/v1"
	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/wg"
)

func newLockKey(t *testing.T) lock.PrivateKey {
	t.Helper()
	k, err := lock.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signedRecord(t *testing.T, k lock.PrivateKey, r lock.Record) *thawrv1.SignedLockRecord {
	t.Helper()
	msg, err := r.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := lock.Sign(k, msg)
	if err != nil {
		t.Fatal(err)
	}
	out := &thawrv1.LockRecord{Generation: r.Generation, Disabled: r.Disabled}
	for _, s := range r.Signers {
		out.Signers = append(out.Signers, &thawrv1.LockSigner{Key: s.Key.String(), PeerId: s.PeerID})
	}
	return &thawrv1.SignedLockRecord{Record: out, Signature: sig.String()}
}

func peerSignature(t *testing.T, k lock.PrivateKey, id, name, key string) string {
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
	return sig.String()
}

// TestLockRPCs walks the signer flow over gRPC: only a signer may list
// peers, records need a signature by the current set, peer signatures
// reach other devices through Sync, and Sync reports a lock key.
func TestLockRPCs(t *testing.T) {
	env := newSyncEnv(t)
	ctx := context.Background()
	aID, aSecret := env.enrol("a")
	bID, bSecret := env.enrol("b")
	ka, kb := newLockKey(t), newLockKey(t)

	if _, err := env.client.ListLockPeers(authCtx(aSecret), &thawrv1.Empty{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("list before lock: %v", err)
	}
	if _, err := env.client.SetLock(authCtx(aSecret), &thawrv1.SetLockRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty record: %v", err)
	}
	first := lock.Record{Generation: 1, Signers: []lock.Signer{{Key: ka.Public(), PeerID: aID}}}
	if _, err := env.client.SetLock(authCtx(aSecret), &thawrv1.SetLockRequest{Lock: signedRecord(t, ka, first)}); err != nil {
		t.Fatalf("SetLock: %v", err)
	}
	// b cannot list, cannot sign, cannot replace the record with its own.
	if _, err := env.client.ListLockPeers(authCtx(bSecret), &thawrv1.Empty{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("b list: %v", err)
	}
	hijack := lock.Record{Generation: 2, Signers: []lock.Signer{{Key: kb.Public(), PeerID: bID}}}
	if _, err := env.client.SetLock(authCtx(bSecret), &thawrv1.SetLockRequest{Lock: signedRecord(t, kb, hijack)}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("hijack record: %v", err)
	}
	list, err := env.client.ListLockPeers(authCtx(aSecret), &thawrv1.Empty{})
	if err != nil {
		t.Fatalf("a list: %v", err)
	}
	if len(list.GetPeers()) != 2 || list.GetHub().GetPublicKey() != testHubKey || list.GetHub().GetSigned() {
		t.Fatalf("list: %v", list)
	}
	var bKey string
	for _, p := range list.GetPeers() {
		if p.GetSigned() || p.GetLockKey() != "" {
			t.Errorf("fresh peer %s: signed=%v lock_key=%q", p.GetName(), p.GetSigned(), p.GetLockKey())
		}
		if p.GetId() == bID {
			bKey = p.GetPublicKey()
		}
	}
	// Sign the hub and b; a signature by b's (non-signer) key is refused,
	// so is one over the wrong key.
	hubSig := peerSignature(t, ka, lock.HubID, lock.HubID, testHubKey)
	if _, err := env.client.SignPeer(authCtx(aSecret), &thawrv1.SignPeerRequest{PeerId: lock.HubID, PublicKey: testHubKey, SignerKey: ka.Public().String(), Signature: hubSig}); err != nil {
		t.Fatalf("sign hub: %v", err)
	}
	bSig := peerSignature(t, kb, bID, "b", bKey)
	if _, err := env.client.SignPeer(authCtx(bSecret), &thawrv1.SignPeerRequest{PeerId: bID, PublicKey: bKey, SignerKey: kb.Public().String(), Signature: bSig}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("non-signer signs: %v", err)
	}
	if _, err := env.client.SignPeer(authCtx(aSecret), &thawrv1.SignPeerRequest{PeerId: bID, PublicKey: testHubKey, SignerKey: ka.Public().String(), Signature: bSig}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := env.client.SignPeer(authCtx(aSecret), &thawrv1.SignPeerRequest{PeerId: bID, PublicKey: bKey, SignerKey: ka.Public().String(), Signature: peerSignature(t, ka, bID, "b", bKey)}); err != nil {
		t.Fatalf("sign b: %v", err)
	}
	// b's netmap carries the record, the hub signature and its own.
	stream, err := env.client.Sync(authCtx(bSecret), &thawrv1.SyncRequest{LockKey: kb.Public().String()})
	if err != nil {
		t.Fatal(err)
	}
	nm, err := recvMap(t, stream)
	if err != nil {
		t.Fatal(err)
	}
	if nm.GetLock().GetRecord().GetGeneration() != 1 || len(nm.GetLock().GetRecord().GetSigners()) != 1 || nm.GetLock().GetRecord().GetSigners()[0].GetKey() != ka.Public().String() {
		t.Errorf("lock in netmap: %v", nm.GetLock())
	}
	if hs := nm.GetHub().GetSignatures(); len(hs) != 1 || hs[0].GetSignerKey() != ka.Public().String() || hs[0].GetSignature() != hubSig {
		t.Errorf("hub signatures: %v", hs)
	}
	if ps := nm.GetPeers(); len(ps) != 1 || ps[0].GetId() != aID || len(ps[0].GetSignatures()) != 0 {
		t.Errorf("a (unsigned) in b's map: %v", ps)
	}
	// The reported lock key shows up for the signer, and a signed
	// rotation by the signer stores the signature in one step.
	list, err = env.client.ListLockPeers(authCtx(aSecret), &thawrv1.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range list.GetPeers() {
		if p.GetId() == bID {
			found = p.GetSigned() && p.GetLockKey() == kb.Public().String()
		}
	}
	if !found {
		t.Errorf("b after sign and sync: %v", list)
	}
	newKey, _ := wg.GenerateKey()
	rot := &thawrv1.RotateKeyRequest{NewPublicKey: newKey.PublicKey().String(), SignerKey: ka.Public().String(),
		Signature: peerSignature(t, ka, aID, "a", newKey.PublicKey().String())}
	if _, err := env.client.RotateKey(authCtx(aSecret), rot); err != nil {
		t.Fatalf("signed rotate: %v", err)
	}
	var seen bool
	for i := 0; i < 5 && !seen; i++ {
		nm, err := recvMap(t, stream)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range nm.GetPeers() {
			if p.GetId() == aID && p.GetPublicKey() == newKey.PublicKey().String() && len(p.GetSignatures()) == 1 {
				seen = true
			}
		}
	}
	if !seen {
		t.Error("b never received a's signed new key")
	}
	if got, _, err := env.lock.ListPeers(ctx); err != nil || len(got) != 2 {
		t.Errorf("service list: %v %v", got, err)
	}
}

// TestSyncRejectsBadLockKey covers the stream error path separately
// because the error only surfaces on the first Recv.
func TestSyncRejectsBadLockKey(t *testing.T) {
	env := newSyncEnv(t)
	_, secret := env.enrol("a")
	stream, err := env.client.Sync(authCtx(secret), &thawrv1.SyncRequest{LockKey: "junk"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recvMap(t, stream); status.Code(err) != codes.InvalidArgument {
		t.Errorf("junk lock key: %v", err)
	}
}

// TestLockEndpoint covers GET /api/v1/lock and the signed field of the
// peer views.
func TestLockEndpoint(t *testing.T) {
	var svc *control.LockService
	env := newRESTEnv(t, func(d *RESTDeps, e *restEnv) {
		svc = control.NewLockService(e.st, time.Now, d.Logger, testHubKey)
		d.Lock = svc
	})
	ctx := context.Background()
	alice := enrolPeer(t, env, "alice")
	bob := enrolPeer(t, env, "markus")
	_, admin := env.login("markus", "adminpassword")

	if rec := env.do(env.handler, session{}, http.MethodGet, "/api/v1/lock", nil, false); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rec.Code)
	}
	show := func() lockView {
		rec := env.do(env.handler, admin, http.MethodGet, "/api/v1/lock", nil, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("lock: %d %s", rec.Code, rec.Body.String())
		}
		var v lockView
		decode(t, rec, &v)
		return v
	}
	peers := func() []peerView {
		rec := env.do(env.local, session{}, http.MethodGet, "/api/v1/peers", nil, false)
		var out []peerView
		decode(t, rec, &out)
		return out
	}
	if v := show(); v.Enabled || len(v.Signers) != 0 || len(v.Unsigned) != 0 {
		t.Errorf("lock off: %+v", v)
	}
	for _, p := range peers() {
		if p.Signed != nil {
			t.Errorf("signed field while lock off: %+v", p)
		}
	}
	ka := newLockKey(t)
	first := lock.Record{Generation: 1, Signers: []lock.Signer{{Key: ka.Public(), PeerID: alice.ID}}}
	msg, _ := first.Bytes()
	sig, _ := lock.Sign(ka, msg)
	if err := svc.Set(ctx, alice, lock.Signed{Record: first, Signature: sig}, nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.Sign(ctx, alice, alice.ID, alice.PublicKey, ka.Public(), mustSig(t, peerSignature(t, ka, alice.ID, alice.Name, alice.PublicKey))); err != nil {
		t.Fatal(err)
	}
	v := show()
	if !v.Enabled || v.Generation != 1 || len(v.Signers) != 1 || v.Signers[0].Peer != alice.Name || v.Signers[0].Fingerprint != lock.Fingerprint(ka.Public()) {
		t.Errorf("lock on: %+v", v)
	}
	if len(v.Unsigned) != 2 || v.Unsigned[0] != lock.HubID || v.Unsigned[1] != bob.Name {
		t.Errorf("unsigned: %v", v.Unsigned)
	}
	for _, p := range peers() {
		want := p.Name == alice.Name
		if p.Signed == nil || *p.Signed != want {
			t.Errorf("signed field of %s: %v", p.Name, p.Signed)
		}
	}
}

func mustSig(t *testing.T, s string) lock.Signature {
	t.Helper()
	sig, err := lock.ParseSignature(s)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}
