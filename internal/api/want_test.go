package api

import (
	"testing"
	"time"

	thawrv1 "github.com/sira-labs/thawr/internal/api/proto/thawr/v1"
)

// TestReportPathWantsPeer: a peer that reports probing or relaying
// toward another makes the other's netmap ask it to reach back, so both
// sides punch at once and meet on the relay (specs 004, 005).
func TestReportPathWantsPeer(t *testing.T) {
	env := newSyncEnv(t)
	aID, aSecret := env.enrol("a")
	bID, bSecret := env.enrol("b")
	stream, err := env.client.Sync(authCtx(bSecret), &thawrv1.SyncRequest{ClientVersion: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	nm, err := recvMap(t, stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.GetPeers()) != 1 || nm.GetPeers()[0].GetWanted() {
		t.Fatalf("b's first map: %v", nm.GetPeers())
	}

	// A direct path asks nothing of b.
	if _, err := env.client.ReportPath(authCtx(aSecret), &thawrv1.PathReport{Paths: []*thawrv1.PathState{{PeerId: bID, State: "direct", Endpoint: "1.2.3.4:5"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.ReportPath(authCtx(aSecret), &thawrv1.PathReport{Paths: []*thawrv1.PathState{{PeerId: bID, State: "probing", Endpoint: "1.2.3.4:5"}}}); err != nil {
		t.Fatal(err)
	}
	// Keepalive maps keep arriving, so bound the wait overall.
	for deadline := time.Now().Add(2 * time.Second); ; {
		if time.Now().After(deadline) {
			t.Fatal("b's netmap never flagged a wanted")
		}
		nm, err = recvMap(t, stream)
		if err != nil {
			t.Fatal(err)
		}
		if p := nm.GetPeers()[0]; p.GetId() == aID && p.GetWanted() {
			break
		}
	}
	// A report about an unknown peer id records nothing.
	if _, err := env.client.ReportPath(authCtx(aSecret), &thawrv1.PathReport{Paths: []*thawrv1.PathState{{PeerId: "no-such-peer", State: "relay"}}}); err != nil {
		t.Fatal(err)
	}
	if env.hub.Wanted("no-such-peer", aID) {
		t.Error("request recorded for an unknown peer")
	}
}
