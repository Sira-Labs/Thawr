package wgtest

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/wg"
)

func TestFakeRecordsAndCloses(t *testing.T) {
	f := New("thawr0")
	var _ wg.Device = f
	ctx := context.Background()
	if err := f.Configure(ctx, wg.Config{ListenPort: 1}); err != nil {
		t.Fatal(err)
	}
	if last, ok := f.Last(); !ok || last.ListenPort != 1 {
		t.Errorf("Last: %+v %v", last, ok)
	}
	if err := f.Close(); err != nil || !f.Closed() {
		t.Errorf("Close: %v closed=%v", err, f.Closed())
	}
	if err := f.Configure(ctx, wg.Config{}); err == nil {
		t.Error("configure after close should fail")
	}
}

func TestFakePeerOperations(t *testing.T) {
	f := New("thawr0")
	ctx := context.Background()
	k1, _ := wg.GenerateKey()
	k2, _ := wg.GenerateKey()
	ep := netip.MustParseAddrPort("203.0.113.1:1000")
	if err := f.Configure(ctx, wg.Config{Peers: []wg.Peer{{PublicKey: k1, Endpoint: ep}, {PublicKey: k2}}}); err != nil {
		t.Fatal(err)
	}
	// A zero endpoint in a later Configure keeps the current one.
	if err := f.Configure(ctx, wg.Config{Peers: []wg.Peer{{PublicKey: k1}, {PublicKey: k2}}}); err != nil {
		t.Fatal(err)
	}
	if got := f.Peers(); got[0].Endpoint != ep {
		t.Errorf("endpoint lost on re-configure: %+v", got)
	}
	ep2 := netip.MustParseAddrPort("203.0.113.2:1000")
	if err := f.SetPeer(ctx, wg.Peer{PublicKey: k2, Endpoint: ep2}); err != nil {
		t.Fatal(err)
	}
	if err := f.RemovePeer(ctx, k1); err != nil {
		t.Fatal(err)
	}
	peers := f.Peers()
	if len(peers) != 1 || peers[0].PublicKey != k2 || peers[0].Endpoint != ep2 {
		t.Fatalf("peers = %+v", peers)
	}
	if len(f.Configs) != 4 {
		t.Errorf("snapshots = %d, want 4", len(f.Configs))
	}
	hs := time.Now()
	f.SetStats(wg.PeerStats{PublicKey: k2, LastHandshake: hs, RxBytes: 5})
	stats, _ := f.Stats(ctx)
	if len(stats) != 1 || stats[0].Endpoint != ep2 || !stats[0].LastHandshake.Equal(hs) || stats[0].RxBytes != 5 {
		t.Errorf("stats = %+v", stats)
	}
}
