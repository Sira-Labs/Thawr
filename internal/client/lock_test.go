package client

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/store"
	"github.com/thedatadudech/thawr/internal/wg"
	"github.com/thedatadudech/thawr/internal/wg/wgtest"
)

func testLockKey(t *testing.T) lock.PrivateKey {
	t.Helper()
	k, err := lock.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signedRecord(t *testing.T, k lock.PrivateKey, r lock.Record) lock.Signed {
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

func peerSig(t *testing.T, k lock.PrivateKey, id, name, key string) PeerSignature {
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
	return PeerSignature{Signer: k.Public().String(), Signature: sig.String()}
}

func TestPinsUpdateLock(t *testing.T) {
	dir := t.TempDir()
	p, err := LoadPins(dir)
	if err != nil {
		t.Fatal(err)
	}
	ka, outsider := testLockKey(t), testLockKey(t)
	if r := p.UpdateLock(nil, ""); r != "" || p.Lock() != nil || p.Enabled() {
		t.Fatalf("nothing offered, nothing pinned: %q", r)
	}
	one := signedRecord(t, ka, lock.Record{Generation: 1, Signers: []lock.Signer{{Key: ka.Public(), PeerID: "a"}}})
	// An expected signer from enrolment gates first contact only, and
	// listing it is not enough: the record must be signed by it.
	if r := p.UpdateLock(&one, outsider.Public().String()); r == "" || p.Lock() != nil {
		t.Fatalf("first record without the expected signer: %q", r)
	}
	both := signedRecord(t, outsider, lock.Record{Generation: 1, Signers: []lock.Signer{{Key: ka.Public(), PeerID: "a"}, {Key: outsider.Public(), PeerID: "x"}}})
	if r := p.UpdateLock(&both, ka.Public().String()); !strings.Contains(r, "signed by "+lock.Fingerprint(outsider.Public())) || p.Lock() != nil {
		t.Fatalf("record listing the expected signer but signed by another: %q", r)
	}
	if r := p.UpdateLock(&both, outsider.Public().String()); r != "" || p.Lock() == nil {
		t.Fatalf("record signed by the expected signer (full key): %q", r)
	}
	p.lock, p.dirty = nil, false
	// The fingerprint alone is not a key and never matches.
	if r := p.UpdateLock(&one, lock.Fingerprint(ka.Public())); r == "" || p.Lock() != nil {
		t.Fatalf("fingerprint accepted as expected signer: %q", r)
	}
	if r := p.UpdateLock(&one, ka.Public().String()); r != "" || !p.Enabled() || p.Lock().Record.Generation != 1 {
		t.Fatalf("first contact: %q", r)
	}
	if r := p.UpdateLock(&one, ""); r != "" {
		t.Errorf("same record again: %q", r)
	}
	if r := p.UpdateLock(nil, ""); r == "" || !p.Enabled() {
		t.Errorf("server offering nothing must keep the pin: %q enabled=%v", r, p.Enabled())
	}
	hijack := signedRecord(t, outsider, lock.Record{Generation: 5, Signers: []lock.Signer{{Key: outsider.Public(), PeerID: "x"}}})
	if r := p.UpdateLock(&hijack, ""); r == "" || p.Lock().Record.Generation != 1 {
		t.Errorf("outsider record: %q gen=%d", r, p.Lock().Record.Generation)
	}
	stale := signedRecord(t, ka, lock.Record{Generation: 1, Signers: []lock.Signer{{Key: ka.Public(), PeerID: "a"}, {Key: outsider.Public(), PeerID: "x"}}})
	if r := p.UpdateLock(&stale, ""); r == "" {
		t.Error("same generation with different content accepted")
	}
	two := signedRecord(t, ka, lock.Record{Generation: 2, Signers: []lock.Signer{{Key: ka.Public(), PeerID: "a"}, {Key: outsider.Public(), PeerID: "x"}}})
	if r := p.UpdateLock(&two, ""); r != "" || len(p.Lock().Record.Signers) != 2 {
		t.Errorf("signed successor: %q", r)
	}
	// The pin is written by Apply and survives a reload.
	if _, _, err := p.Apply(pinNetMap(testKey(t)), time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	again, err := LoadPins(dir)
	if err != nil || again.Lock() == nil || again.Lock().Record.Generation != 2 {
		t.Fatalf("reload: %+v %v", again.Lock(), err)
	}
	off := signedRecord(t, outsider, lock.Record{Generation: 3, Disabled: true, Signers: two.Record.Signers})
	if r := again.UpdateLock(&off, ""); r != "" || again.Enabled() || again.Lock().Record.Generation != 3 {
		t.Errorf("disable by the added signer: %q enabled=%v", r, again.Enabled())
	}
	// A pinned record that does not verify is a corrupt file, not a
	// fresh start.
	bad := pinFile{Peers: map[string]pinEntry{}, Lock: &lock.Signed{Record: lock.Record{Generation: 9, Signers: []lock.Signer{{Key: ka.Public(), PeerID: "a"}}}}}
	data, _ := json.Marshal(bad)
	if err := writeSecret(dir, PinsFile, data); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPins(dir); err == nil {
		t.Error("unsigned pinned record loaded")
	}
}

func TestPinsHoldUnsigned(t *testing.T) {
	p, err := LoadPins(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ka, outsider := testLockKey(t), testLockKey(t)
	set := lock.Record{Generation: 1, Signers: []lock.Signer{{Key: ka.Public(), PeerID: "a"}}}
	hub, kb, kc, kd := testKey(t), testKey(t), testKey(t), testKey(t)
	now := time.Now()
	nm := pinNetMap(hub,
		Peer{ID: "b", Name: "b", PublicKey: kb, IPv4: "100.64.0.3", Signatures: []PeerSignature{peerSig(t, ka, "b", "b", kb)}},
		Peer{ID: "c", Name: "c", PublicKey: kc, IPv4: "100.64.0.4", Signatures: []PeerSignature{peerSig(t, outsider, "c", "c", kc)}},
		Peer{ID: "d", Name: "d", PublicKey: kd, IPv4: "100.64.0.5", ViaHub: true},
		Peer{ID: "e", Name: "e", PublicKey: kb, IPv4: "100.64.0.6", Signatures: []PeerSignature{peerSig(t, ka, "b", "b", kb)}},
	)
	out, held := p.HoldUnsigned(nm, set, now, nil)
	if out.Hub.PublicKey != "" || heldNames(held) != "hub,c,e" {
		t.Fatalf("unsigned hub and peers: hub=%q held=%s", out.Hub.PublicKey, heldNames(held))
	}
	for _, h := range held {
		if h.Reason != HeldUnsigned || h.Since != now {
			t.Errorf("held %s: %+v", h.Name, h)
		}
	}
	if len(out.Peers) != 2 || out.Peers[0].Name != "b" || out.Peers[1].Name != "d" {
		t.Errorf("passed: %+v", out.Peers)
	}
	if e := p.peers["b"]; e.ID != "b" || e.Key != kb || !p.dirty {
		t.Errorf("signed peer not accepted into the pins: %+v dirty=%v", e, p.dirty)
	}
	// Signing the hub releases it; Since survives for the rest.
	nm.Hub.Signatures = []PeerSignature{peerSig(t, ka, lock.HubID, lock.HubID, hub)}
	later := now.Add(time.Minute)
	out, held = p.HoldUnsigned(nm, set, later, held)
	if out.Hub.PublicKey != hub || p.hub != hub || heldNames(held) != "c,e" || held[0].Since != now {
		t.Errorf("after hub signature: hub=%q held=%+v", out.Hub.PublicKey, held)
	}
	// A signed rotation replaces the pin without a trust step.
	kb2 := testKey(t)
	nm.Peers[0].PublicKey, nm.Peers[0].Signatures = kb2, []PeerSignature{peerSig(t, ka, "b", "b", kb2)}
	_, held = p.HoldUnsigned(nm, set, later, held)
	applied, heldKeys, err := p.Apply(nm, later, nil)
	if err != nil {
		t.Fatal(err)
	}
	if heldNames(held) != "c,e" || len(heldKeys) != 0 || p.peers["b"].Key != kb2 || len(applied.Peers) != 4 {
		t.Errorf("signed rotation: held=%s keys=%v pin=%s", heldNames(held), heldKeys, p.peers["b"].Key)
	}
}

func waitStatus(t *testing.T, lc *LocalClient, what string, cond func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := lc.Status(context.Background())
		if err == nil && cond(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not reached within 5s: %+v", what, st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestDaemonNetworkLock walks the owner flow end to end against the
// fake device: init on a, an unsigned enrolment held on b, sign, a
// signed rotation without trust, an unsigned rotation held, a record
// from an outside key refused, add-signer, disable and re-init.
func TestDaemonNetworkLock(t *testing.T) {
	cp := newControlPlane(t)
	ctx := context.Background()
	dirA, dirB := t.TempDir(), t.TempDir()
	cp.enrol(dirA, "a")
	cp.enrol(dirB, "b")
	a, fakeA, stopA := startDaemon(t, dirA)
	defer stopA()
	b, fakeB, stopB := startDaemon(t, dirB)
	defer stopB()
	waitApplied(t, a, func(nm NetMap) bool { return len(nm.Peers) == 1 })
	waitApplied(t, b, func(nm NetMap) bool { return len(nm.Peers) == 1 })
	lcA, lcB := NewLocalClient(a.opts.Socket), NewLocalClient(b.opts.Socket)

	if _, err := lcA.LockSign(ctx, "all"); err == nil {
		t.Fatal("sign before init succeeded")
	} else if le := new(LocalError); !errors.As(err, &le) || le.Status != http.StatusForbidden {
		t.Fatalf("sign before init: %v", err)
	}
	res, err := lcA.LockInit(ctx)
	if err != nil {
		t.Fatalf("lock init: %v", err)
	}
	if res.Generation != 1 || len(res.Signed) != 3 || res.Signed[0].Name != "hub" || res.PublicKey == "" {
		t.Fatalf("init result: %+v", res)
	}
	keyA, err := LoadLockKey(dirA)
	if err != nil || keyA.IsZero() || keyA.Public().String() != res.PublicKey {
		t.Fatalf("lock key file: %v", err)
	}
	// Right after init the daemon re-applies the netmap it had before
	// the server carried the record, so Rejected reads "server offers
	// no lock record" until the next netmap; wait for that too.
	stA2 := waitStatus(t, lcA, "a lock on", func(s Status) bool { return s.Lock.Enabled && s.Lock.SelfSigned && s.Lock.Rejected == "" })
	if !stA2.Lock.Signer || !stA2.Lock.HasKey || stA2.Lock.Generation != 1 || len(stA2.Lock.Signers) != 1 || stA2.Lock.Signers[0].Name != "a" || stA2.Lock.Rejected != "" {
		t.Errorf("a status: %+v", stA2.Lock)
	}
	stB2 := waitStatus(t, lcB, "b lock on", func(s Status) bool { return s.Lock.Enabled && s.Lock.SelfSigned })
	if stB2.Lock.Signer || stB2.Lock.HasKey || len(stB2.Held) != 0 || len(stB2.Peers) != 1 || stB2.Peers[0].Path == PathUnsigned {
		t.Errorf("b status: lock=%+v held=%+v peers=%+v", stB2.Lock, stB2.Held, stB2.Peers)
	}
	if last, _ := fakeB.Last(); len(last.Peers) != 2 {
		t.Errorf("b device after init: %+v", last.Peers)
	}

	// A new enrolment is held as unsigned everywhere; trust cannot
	// release it, only a signer can.
	dirC := t.TempDir()
	stC := cp.enrol(dirC, "c")
	keyC, _ := LoadKey(dirC)
	stB3 := waitStatus(t, lcB, "c held on b", func(s Status) bool { return len(s.Held) == 1 })
	if h := stB3.Held[0]; h.Name != "c" || h.Reason != HeldUnsigned || h.OfferedKey != keyC.PublicKey().String() || h.PinnedKey != "" {
		t.Errorf("held c: %+v", h)
	}
	if len(stB3.Peers) != 2 || stB3.Peers[0].Name != "c" || stB3.Peers[0].Path != PathUnsigned {
		t.Errorf("c row: %+v", stB3.Peers)
	}
	if last, _ := fakeB.Last(); len(last.Peers) != 2 {
		t.Errorf("unsigned peer on b's device: %+v", last.Peers)
	}
	if _, err := lcB.Trust(ctx, "c"); err == nil {
		t.Error("trust released an unsigned peer")
	}
	if _, err := lcB.LockSign(ctx, "c"); err == nil {
		t.Error("non-signer signed")
	}
	res, err = lcA.LockSign(ctx, "c")
	if err != nil || len(res.Signed) != 1 || res.Signed[0].Name != "c" {
		t.Fatalf("sign c: %+v %v", res, err)
	}
	waitStatus(t, lcB, "c released on b", func(s Status) bool { return len(s.Held) == 0 && len(s.Peers) == 2 })
	if last, _ := fakeB.Last(); len(last.Peers) != 3 {
		t.Errorf("b device after signing c: %+v", last.Peers)
	}
	if _, err := lcA.LockSign(ctx, "all"); err != nil {
		t.Errorf("sign all with nothing unsigned: %v", err)
	}

	// A signer's rotation is signed on the way: b switches without trust.
	if err := lcA.RotateKey(ctx); err != nil {
		t.Fatalf("rotate a: %v", err)
	}
	newA, _ := LoadKey(dirA)
	waitStatus(t, lcB, "a's new key on b", func(s Status) bool {
		for _, p := range s.Peers {
			if p.Name == "a" && p.PublicKey == newA.PublicKey().String() && p.Path != PathUnsigned && p.Path != PathKeyChanged {
				return true
			}
		}
		return false
	})
	if st, _ := lcB.Status(ctx); len(st.Held) != 0 {
		t.Errorf("held after signed rotation: %+v", st.Held)
	}
	// b's rotation is unsigned (no lock key): a holds it until signed.
	if err := lcB.RotateKey(ctx); err != nil {
		t.Fatalf("rotate b: %v", err)
	}
	waitStatus(t, lcA, "b held on a", func(s Status) bool {
		return len(s.Held) == 1 && s.Held[0].Name == "b" && s.Held[0].Reason == HeldUnsigned
	})
	if res, err := lcA.LockSign(ctx, "all"); err != nil || len(res.Signed) != 1 || res.Signed[0].Name != "b" {
		t.Fatalf("sign all: %+v %v", res, err)
	}
	waitStatus(t, lcA, "b released on a", func(s Status) bool { return len(s.Held) == 0 })

	// A record signed by an outside key, written straight into the
	// server's store, is refused and the pin stays.
	outsider := testLockKey(t)
	hijack := signedRecord(t, outsider, lock.Record{Generation: 7, Signers: []lock.Signer{{Key: outsider.Public(), PeerID: stC.PeerID}}})
	good, err := cp.st.Meta().Get(ctx, store.MetaLockRecord)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(hijack)
	if err := cp.st.Meta().Set(ctx, store.MetaLockRecord, string(raw)); err != nil {
		t.Fatal(err)
	}
	cp.hub.Changed()
	stB4 := waitStatus(t, lcB, "hijack refused on b", func(s Status) bool { return s.Lock.Rejected != "" })
	if !stB4.Lock.Enabled || stB4.Lock.Generation != 1 || len(stB4.Held) != 0 {
		t.Errorf("after hijack: %+v held=%+v", stB4.Lock, stB4.Held)
	}
	if err := cp.st.Meta().Set(ctx, store.MetaLockRecord, good); err != nil {
		t.Fatal(err)
	}
	cp.hub.Changed()
	waitStatus(t, lcB, "record restored", func(s Status) bool { return s.Lock.Rejected == "" })

	// b creates a key, a adds it as signer, b disables, b re-enables.
	kres, err := lcB.LockKey(ctx)
	if err != nil || kres.PublicKey == "" {
		t.Fatalf("lock key: %+v %v", kres, err)
	}
	if again, err := lcB.LockKey(ctx); err != nil || again.PublicKey != kres.PublicKey {
		t.Errorf("lock key twice: %+v %v", again, err)
	}
	// The server's reported key must match what the person read on b.
	wrong := testLockKey(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err = lcA.LockAddSigner(ctx, "b", wrong.Public().String())
		if le := new(LocalError); errors.As(err, &le) && le.Status == http.StatusConflict && strings.Contains(le.Message, "mismatch") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("add signer with the wrong fingerprint: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := lcA.LockAddSigner(ctx, "b", ""); err == nil {
		t.Error("add signer without a key succeeded")
	}
	if _, err := lcA.LockAddSigner(ctx, "b", lock.Fingerprint(wrong.Public())); err == nil {
		t.Error("add signer with a fingerprint instead of a key succeeded")
	}
	if st, _ := lcB.Status(ctx); st.Lock.Signer || st.Lock.Generation != 1 {
		t.Errorf("record changed by a refused add-signer: %+v", st.Lock)
	}
	if res, err = lcA.LockAddSigner(ctx, "b", kres.PublicKey); err != nil || res.Generation != 2 {
		t.Fatalf("add signer: %+v %v", res, err)
	}
	stB5 := waitStatus(t, lcB, "b is a signer", func(s Status) bool { return s.Lock.Signer })
	if stB5.Lock.Generation != 2 || len(stB5.Lock.Signers) != 2 {
		t.Errorf("b after add-signer: %+v", stB5.Lock)
	}
	if res, err := lcB.LockDisable(ctx); err != nil || res.Generation != 3 {
		t.Fatalf("disable: %+v %v", res, err)
	}
	waitStatus(t, lcA, "lock off on a", func(s Status) bool { return !s.Lock.Enabled && s.Lock.Generation == 3 })
	if _, err := lcA.LockSign(ctx, "all"); err == nil {
		t.Error("sign with the lock off succeeded")
	}
	if res, err := lcB.LockInit(ctx); err != nil || res.Generation != 4 {
		t.Fatalf("re-init: %+v %v", res, err)
	}
	stA6 := waitStatus(t, lcA, "lock on again", func(s Status) bool { return s.Lock.Enabled && s.Lock.Generation == 4 })
	if stA6.Lock.Signer || len(stA6.Lock.Signers) != 1 || stA6.Lock.Signers[0].Name != "b" || !stA6.Lock.SelfSigned {
		t.Errorf("a after re-init: %+v", stA6.Lock)
	}
	if last, _ := fakeA.Last(); len(last.Peers) != 3 {
		t.Errorf("a device after re-init: %+v", last.Peers)
	}
}

// TestForgetRemovesLockKey: `down --forget` drops the lock key with
// the enrolment, and pins.json stays.
func TestForgetRemovesLockKey(t *testing.T) {
	dir := t.TempDir()
	if err := SaveLockKey(dir, testLockKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := writeSecret(dir, PinsFile, []byte(`{"hub":"","peers":{}}`)); err != nil {
		t.Fatal(err)
	}
	if err := Forget(dir); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadLockKey(dir); err != nil || !k.IsZero() {
		t.Errorf("lock key after forget: %v %v", k.IsZero(), err)
	}
	if _, err := LoadPins(dir); err != nil {
		t.Errorf("pins after forget: %v", err)
	}
}

// TestDaemonLockSignerFailsClosed: a device enrolled with --lock-signer
// applies nothing until a record signed by that key arrives, and never
// when the record is signed by another key.
func TestDaemonLockSignerFailsClosed(t *testing.T) {
	cp := newControlPlane(t)
	ctx := context.Background()
	ka, wrong := testLockKey(t), testLockKey(t)
	dirA, dirC, dirD := t.TempDir(), t.TempDir(), t.TempDir()
	cp.enrol(dirA, "a")
	if err := SaveLockKey(dirA, ka); err != nil {
		t.Fatal(err)
	}
	cp.enrolWith(dirC, "c", func(o *Options) { o.LockSigner = ka.Public().String() })
	cp.enrolWith(dirD, "d", func(o *Options) { o.LockSigner = wrong.Public().String() })
	a, _, stopA := startDaemon(t, dirA)
	defer stopA()
	c, fakeC, stopC := startDaemon(t, dirC)
	defer stopC()
	d, fakeD, stopD := startDaemon(t, dirD)
	defer stopD()
	waitApplied(t, a, func(nm NetMap) bool { return len(nm.Peers) == 2 })
	lcA, lcC, lcD := NewLocalClient(a.opts.Socket), NewLocalClient(c.opts.Socket), NewLocalClient(d.opts.Socket)
	for _, x := range []struct {
		lc   *LocalClient
		fake *wgtest.Fake
		name string
	}{{lcC, fakeC, "c"}, {lcD, fakeD, "d"}} {
		st := waitStatus(t, x.lc, x.name+" waiting for the lock", func(s Status) bool {
			return s.Server.State == ServerConnected && strings.Contains(s.Lock.Rejected, "waiting for a lock record")
		})
		if st.Lock.Enabled || len(st.Peers) != 0 || st.Hub != nil {
			t.Errorf("%s before the lock: %+v", x.name, st)
		}
		if last, _ := x.fake.Last(); len(last.Peers) != 0 {
			t.Errorf("%s device before the lock: %+v", x.name, last.Peers)
		}
	}
	if _, err := lcA.LockInit(ctx); err != nil {
		t.Fatalf("lock init: %v", err)
	}
	stC := waitStatus(t, lcC, "c adopts the record", func(s Status) bool { return s.Lock.Enabled && len(s.Peers) == 2 })
	if stC.Lock.Rejected != "" || len(stC.Held) != 0 {
		t.Errorf("c after the lock: %+v", stC.Lock)
	}
	if last, _ := fakeC.Last(); len(last.Peers) != 3 {
		t.Errorf("c device after the lock: %+v", last.Peers)
	}
	stD := waitStatus(t, lcD, "d refuses the record", func(s Status) bool { return strings.Contains(s.Lock.Rejected, "does not name the signer") })
	if stD.Lock.Enabled || len(stD.Peers) != 0 {
		t.Errorf("d after the lock: %+v", stD)
	}
	if last, _ := fakeD.Last(); len(last.Peers) != 0 {
		t.Errorf("d device after a foreign record: %+v", last.Peers)
	}
}
