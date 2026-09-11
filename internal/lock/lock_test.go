package lock

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func mustKey(t *testing.T) PrivateKey {
	t.Helper()
	k, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyRoundTrips(t *testing.T) {
	k := mustKey(t)
	again, err := ParsePrivateKey(k.String())
	if err != nil || again.Public() != k.Public() {
		t.Fatalf("private key round trip: %v", err)
	}
	pub, err := ParsePublicKey(k.Public().String())
	if err != nil || pub != k.Public() {
		t.Fatalf("public key round trip: %v", err)
	}
	if fp := Fingerprint(pub); len(fp) != 8 {
		t.Errorf("fingerprint %q", fp)
	}
	sig, err := Sign(k, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseSignature(sig.String()); err != nil || parsed != sig {
		t.Errorf("signature round trip: %v", err)
	}
	if !Verify(pub, []byte("msg"), sig) || Verify(pub, []byte("msh"), sig) {
		t.Error("verify")
	}
	for _, bad := range []string{"", "not base64!", "AAAA"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("public key %q accepted", bad)
		}
		if _, err := ParsePrivateKey(bad); err == nil {
			t.Errorf("private key %q accepted", bad)
		}
		if _, err := ParseSignature(bad); err == nil {
			t.Errorf("signature %q accepted", bad)
		}
	}
	if _, err := Sign(PrivateKey{}, []byte("x")); err == nil {
		t.Error("signing with an empty key succeeded")
	}
	if !(PrivateKey{}).IsZero() || (PrivateKey{}).String() != "" || !(PublicKey{}).IsZero() {
		t.Error("zero values")
	}
	var viaJSON struct {
		Key PublicKey `json:"key"`
		Sig Signature `json:"sig"`
	}
	data, _ := json.Marshal(map[string]string{"key": pub.String(), "sig": sig.String()})
	if err := json.Unmarshal(data, &viaJSON); err != nil || viaJSON.Key != pub || viaJSON.Sig != sig {
		t.Errorf("json: %v", err)
	}
}

// TestPeerRecordGolden pins the canonical bytes: a change here breaks
// every signature ever made.
func TestPeerRecordGolden(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	got, err := PeerRecord{ID: "p1", Name: "nas", Key: key}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := "74686177722f706565722f76310a" + // "thawr/peer/v1\n"
		"0002" + "7031" + // id
		"0003" + "6e6173" + // name
		"0020" + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if hex.EncodeToString(got) != want {
		t.Errorf("peer record bytes\n got %x\nwant %s", got, want)
	}
	if _, err := (PeerRecord{Name: "x"}).Bytes(); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty id: %v", err)
	}
	if _, err := (PeerRecord{ID: "x", Name: strings.Repeat("n", maxField+1)}).Bytes(); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversized name: %v", err)
	}
}

func TestLockRecordGolden(t *testing.T) {
	var k PublicKey
	for i := range k {
		k[i] = 0x11
	}
	got, err := Record{Generation: 1, Signers: []Signer{{Key: k, PeerID: "p1"}}}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := "74686177722f6c6f636b2f76310a" + // "thawr/lock/v1\n"
		"0000000000000001" + "00" + "0001" +
		"0020" + strings.Repeat("11", 32) +
		"0002" + "7031"
	if hex.EncodeToString(got) != want {
		t.Errorf("lock record bytes\n got %x\nwant %s", got, want)
	}
	// Signer order does not change the bytes.
	a, b := mustKey(t).Public(), mustKey(t).Public()
	r1 := Record{Generation: 2, Signers: []Signer{{a, "pa"}, {b, "pb"}}}
	r2 := Record{Generation: 2, Signers: []Signer{{b, "pb"}, {a, "pa"}}}
	b1, _ := r1.Bytes()
	b2, _ := r2.Bytes()
	if !bytes.Equal(b1, b2) {
		t.Error("signer order changed the canonical bytes")
	}
	if !r1.Has(a) || r1.Has(PublicKey{}) {
		t.Error("Has")
	}
	if key, ok := r1.SignerKey("pb"); !ok || key != b {
		t.Error("SignerKey")
	}
	if _, ok := r1.SignerKey("nobody"); ok {
		t.Error("SignerKey unknown")
	}
	for name, bad := range map[string]Record{
		"no signers":        {Generation: 1},
		"empty key":         {Generation: 1, Signers: []Signer{{PeerID: "p"}}},
		"empty peer":        {Generation: 1, Signers: []Signer{{Key: a}}},
		"duplicate key":     {Generation: 1, Signers: []Signer{{a, "p1"}, {a, "p2"}}},
		"duplicate peer id": {Generation: 1, Signers: []Signer{{a, "p1"}, {b, "p1"}}},
	} {
		if _, err := bad.Bytes(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !(Record{Generation: 1, Disabled: true}).Enabled() == false {
		t.Error("disabled record enabled")
	}
	if !r1.Enabled() {
		t.Error("record with signers not enabled")
	}
}

func TestPeerRecordTamper(t *testing.T) {
	k := mustKey(t)
	var key [32]byte
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))
	rec := PeerRecord{ID: "p1", Name: "nas", Key: key}
	msg, _ := rec.Bytes()
	sig, _ := Sign(k, msg)
	if !Verify(k.Public(), msg, sig) {
		t.Fatal("signature does not verify")
	}
	for name, mod := range map[string]func(r *PeerRecord){
		"id":   func(r *PeerRecord) { r.ID = "p2" },
		"name": func(r *PeerRecord) { r.Name = "nas2" },
		"key":  func(r *PeerRecord) { r.Key[0] ^= 1 },
	} {
		tampered := rec
		mod(&tampered)
		m, _ := tampered.Bytes()
		if Verify(k.Public(), m, sig) {
			t.Errorf("signature survived a changed %s", name)
		}
	}
	// A lock record signed with the same key never verifies as a peer record.
	lockMsg, _ := Record{Generation: 1, Signers: []Signer{{k.Public(), "p1"}}}.Bytes()
	lockSig, _ := Sign(k, lockMsg)
	if Verify(k.Public(), msg, lockSig) {
		t.Error("cross-record signature verified")
	}
}

func signed(t *testing.T, k PrivateKey, r Record) Signed {
	t.Helper()
	msg, err := r.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(k, msg)
	if err != nil {
		t.Fatal(err)
	}
	return Signed{Record: r, Signature: sig}
}

func TestAccept(t *testing.T) {
	a, b, outsider := mustKey(t), mustKey(t), mustKey(t)
	first := signed(t, a, Record{Generation: 1, Signers: []Signer{{a.Public(), "pa"}}})
	if err := Accept(nil, first); err != nil {
		t.Fatalf("first contact: %v", err)
	}
	// First contact still requires the record to be signed by one of its own keys.
	garbage := first
	garbage.Signature[0] ^= 1
	if err := Accept(nil, garbage); !errors.Is(err, ErrNotSigned) {
		t.Errorf("garbage first record: %v", err)
	}
	forged := signed(t, outsider, Record{Generation: 1, Signers: []Signer{{a.Public(), "pa"}}})
	if err := Accept(nil, forged); !errors.Is(err, ErrNotSigned) {
		t.Errorf("first record signed by an outsider: %v", err)
	}

	cur := first.Record
	// Adding b, signed by a: accepted.
	two := signed(t, a, Record{Generation: 2, Signers: []Signer{{a.Public(), "pa"}, {b.Public(), "pb"}}})
	if err := Accept(&cur, two); err != nil {
		t.Errorf("add signer: %v", err)
	}
	// The new signer may not vouch for its own addition.
	selfAdded := signed(t, b, two.Record)
	if err := Accept(&cur, selfAdded); !errors.Is(err, ErrNotSigned) {
		t.Errorf("self-added signer accepted: %v", err)
	}
	// Replay and stale generations.
	if err := Accept(&cur, first); !errors.Is(err, ErrStale) {
		t.Errorf("replay: %v", err)
	}
	if err := Accept(&two.Record, first); !errors.Is(err, ErrStale) {
		t.Errorf("older generation: %v", err)
	}
	// An outsider cannot replace the set even with a higher generation.
	hijack := signed(t, outsider, Record{Generation: 9, Signers: []Signer{{outsider.Public(), "px"}}})
	if err := Accept(&cur, hijack); !errors.Is(err, ErrNotSigned) {
		t.Errorf("hijack: %v", err)
	}
	// Disable must be signed by a current key; then the lock is off.
	off := signed(t, b, Record{Generation: 3, Disabled: true})
	if err := Accept(&two.Record, off); err != nil {
		t.Errorf("disable by b: %v", err)
	}
	if off.Record.Enabled() {
		t.Error("disabled record reports enabled")
	}
	offByOutsider := signed(t, outsider, Record{Generation: 3, Disabled: true})
	if err := Accept(&two.Record, offByOutsider); !errors.Is(err, ErrNotSigned) {
		t.Errorf("disable by outsider: %v", err)
	}
	// Malformed next record.
	if err := Accept(&cur, Signed{Record: Record{Generation: 5}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid record: %v", err)
	}
	// JSON round trip of a signed record keeps it verifiable.
	data, _ := json.Marshal(two)
	var back Signed
	if err := json.Unmarshal(data, &back); err != nil || Accept(&cur, back) != nil {
		t.Errorf("json round trip: %v", err)
	}
}
