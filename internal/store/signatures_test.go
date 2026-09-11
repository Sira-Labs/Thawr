package store

import (
	"context"
	"testing"
	"time"
)

func TestSignaturesPutListDelete(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	at := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	rows := []PeerSignature{
		{PeerID: "p1", PublicKey: "K1=", SignerKey: "S1=", Signature: "sig1", SignedAt: at},
		{PeerID: "p1", PublicKey: "K1=", SignerKey: "S2=", Signature: "sig2", SignedAt: at},
		{PeerID: "hub", PublicKey: "H=", SignerKey: "S1=", Signature: "sigh", SignedAt: at},
	}
	for _, r := range rows {
		if err := s.Signatures().Put(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Signatures().Put(ctx, PeerSignature{PeerID: "p1"}); err == nil {
		t.Error("incomplete signature accepted")
	}
	// Replacing the same (peer, key, signer) updates in place.
	if err := s.Signatures().Put(ctx, PeerSignature{PeerID: "p1", PublicKey: "K1=", SignerKey: "S1=", Signature: "sig1b", SignedAt: at.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	all, err := s.Signatures().ListAll(ctx)
	if err != nil || len(all) != 3 {
		t.Fatalf("list: %d %v", len(all), err)
	}
	if all[0].PeerID != "hub" || all[1].Signature != "sig1b" || !all[1].SignedAt.Equal(at.Add(time.Hour)) || all[2].SignerKey != "S2=" {
		t.Errorf("rows: %+v", all)
	}
	if err := s.Signatures().DeletePeer(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if all, _ = s.Signatures().ListAll(ctx); len(all) != 1 || all[0].PeerID != "hub" {
		t.Errorf("after delete: %+v", all)
	}
	if err := s.Signatures().DeleteAll(ctx); err != nil {
		t.Fatal(err)
	}
	if all, _ = s.Signatures().ListAll(ctx); len(all) != 0 {
		t.Errorf("after delete all: %+v", all)
	}
	// The lock record is a plain meta value.
	if err := s.Meta().Set(ctx, MetaLockRecord, `{"record":{"generation":1}}`); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Meta().Get(ctx, MetaLockRecord); err != nil || v == "" {
		t.Errorf("lock record: %q %v", v, err)
	}
}
