package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPeerRelayCapable(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for id, capable := range map[string]bool{"a": false, "b": true} {
		p := Peer{ID: id, Name: "n-" + id, Kind: KindHuman, Mode: ModeAgent, PublicKey: "k-" + id,
			IPv4: "100.64.0." + map[string]string{"a": "2", "b": "3"}[id], RelayCapable: capable, CreatedAt: time.Now().UTC()}
		if err := s.Peers().Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if p, err := s.Peers().GetByID(ctx, "b"); err != nil || !p.RelayCapable {
		t.Errorf("relay_capable not stored on create: %+v %v", p, err)
	}

	changed, err := s.Peers().SetRelayCapable(ctx, "a", true)
	if err != nil || !changed {
		t.Fatalf("SetRelayCapable = %v, %v", changed, err)
	}
	if changed, err := s.Peers().SetRelayCapable(ctx, "a", true); err != nil || changed {
		t.Errorf("repeat SetRelayCapable = %v, %v; want unchanged", changed, err)
	}
	if p, _ := s.Peers().GetByID(ctx, "a"); !p.RelayCapable {
		t.Error("relay_capable not stored")
	}
	if changed, err := s.Peers().SetRelayCapable(ctx, "a", false); err != nil || !changed {
		t.Errorf("clearing: %v, %v", changed, err)
	}
	if p, _ := s.Peers().GetByID(ctx, "a"); p.RelayCapable {
		t.Error("relay_capable not cleared")
	}
	if _, err := s.Peers().SetRelayCapable(ctx, "nobody", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown peer: %v", err)
	}
}
