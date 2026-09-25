package client

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

func TestNATType(t *testing.T) {
	local := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	lan := control.Endpoint{Addr: netip.MustParseAddrPort("192.0.2.10:41820"), Kind: control.EndpointLocal}
	refl := control.Endpoint{Addr: netip.MustParseAddrPort("203.0.113.5:4444"), Kind: control.EndpointReflexive}
	same := control.Endpoint{Addr: netip.MustParseAddrPort("192.0.2.10:41820"), Kind: control.EndpointReflexive}
	cases := []struct {
		name      string
		eps       []control.Endpoint
		symmetric bool
		want      string
		reflexive int
	}{
		{"no stun", []control.Endpoint{lan}, false, NATUnknown, 0},
		{"cone", []control.Endpoint{lan, refl}, false, NATCone, 1},
		{"public address", []control.Endpoint{lan, same}, false, NATNone, 1},
		{"symmetric", []control.Endpoint{lan, refl}, true, NATSymmetric, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := natStatus(local, tc.eps, tc.symmetric)
			if got.Type != tc.want || len(got.Reflexive) != tc.reflexive || len(got.Local) != 1 {
				t.Errorf("got %+v, want type %s with %d reflexive", got, tc.want, tc.reflexive)
			}
		})
	}
}

// TestStatusServerStates covers connected → cached when the server goes
// away, and reconnecting when a daemon starts without a netmap.
func TestStatusServerStates(t *testing.T) {
	cp := newControlPlane(t)
	dirA, dirB := t.TempDir(), t.TempDir()
	cp.enrol(dirA, "a")
	cp.enrol(dirB, "b")
	d, _, stop := startDaemon(t, dirA)
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return nm.Hub.PublicKey != "" })
	lc := NewLocalClient(d.opts.Socket)
	st, err := lc.Status(context.Background())
	if err != nil || st.Server.State != ServerConnected || st.Server.Attempt != 0 || st.Server.NextRetryAt != nil || st.Server.LastMessageAt == nil {
		t.Fatalf("connected status: %+v err=%v", st.Server, err)
	}
	if st.Hub == nil || st.Hub.Kind != "server" || st.Hub.Path != "unreachable" {
		t.Errorf("hub without handshake: %+v", st.Hub)
	}

	cp.ts.CloseClientConnections()
	cp.ts.Close()
	waitFor(t, "cached state", func() bool {
		st, err := lc.Status(context.Background())
		return err == nil && st.Server.State == ServerCached && st.Server.UnreachableSince != nil && st.Server.Attempt >= 1
	})
	st, _ = lc.Status(context.Background())
	if st.Server.Generation == 0 || st.Server.LastError == "" || st.Server.NextRetryAt == nil {
		t.Errorf("cached status: %+v", st.Server)
	}

	// A fresh daemon with no cache and no server is reconnecting.
	d2, _, stop2 := startDaemon(t, dirB)
	defer stop2()
	lc2 := NewLocalClient(d2.opts.Socket)
	waitFor(t, "reconnecting state", func() bool {
		st, err := lc2.Status(context.Background())
		return err == nil && st.Server.State == ServerReconnecting && st.Server.Attempt >= 1 && st.Server.UnreachableSince != nil && st.Server.Generation == 0
	})
}

// TestStaticPeerViaHub: a static (mobile) peer of the same owner shows
// up as "via hub" in status, gets no WireGuard peer of its own, and its
// address is routed to the hub.
func TestStaticPeerViaHub(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	cp.enrol(dir, "a")
	d, fake, stop := startDaemon(t, dir)
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return nm.Hub.PublicKey != "" })

	phoneKey, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	phone := store.Peer{ID: "phone", Name: "markus-phone", Kind: store.KindHuman, Mode: store.ModeStatic, OwnerID: cp.admin.UserID,
		PublicKey: phoneKey.PublicKey().String(), IPv4: "100.64.0.21", CreatedAt: time.Now()}
	if err := cp.st.Peers().Create(context.Background(), phone); err != nil {
		t.Fatal(err)
	}
	if _, err := cp.st.Meta().IncrementGeneration(context.Background()); err != nil {
		t.Fatal(err)
	}
	cp.hub.Changed()
	nm := waitApplied(t, d, func(nm NetMap) bool { return len(nm.Peers) == 1 })
	if p := nm.Peers[0]; !p.ViaHub || p.Name != "markus-phone" || p.Owner != "markus" {
		t.Fatalf("netmap phone: %+v", p)
	}

	last, ok := fake.Last()
	if !ok || len(last.Peers) != 1 || last.Peers[0].PublicKey != cp.hubKey.PublicKey() {
		t.Errorf("device peers: %+v (want only the hub)", last.Peers)
	}
	routed := false
	for _, a := range last.Peers[0].AllowedIPs {
		routed = routed || a.String() == "100.64.0.21/32"
	}
	if !routed {
		t.Errorf("hub allowed ips lack the phone: %v", last.Peers[0].AllowedIPs)
	}
	st, err := NewLocalClient(d.opts.Socket).Status(context.Background())
	if err != nil || len(st.Peers) != 1 || st.Peers[0].Path != PathHub || st.Peers[0].Kind != "human" || len(st.Peers[0].EndpointCandidates) != 0 {
		t.Errorf("status: %+v err=%v", st.Peers, err)
	}
	if f, ok := fake.LastFilter(); !ok || !slices.Contains(f.Visible, netip.MustParseAddr("100.64.0.21")) {
		t.Errorf("filter visible set lacks the phone: %+v", f.Visible)
	}
	// A phone has no path of its own: ping answers "hub" without probing.
	res, err := NewLocalClient(d.opts.Socket).Ping(context.Background(), "markus-phone")
	if err != nil || res.State != PathHub || res.Peer != "markus-phone" || res.Endpoint != "" {
		t.Errorf("ping via-hub peer: %+v err=%v", res, err)
	}
	if _, err := NewLocalClient(d.opts.Socket).Ping(context.Background(), "nobody"); err == nil {
		t.Error("ping of an unknown peer succeeded")
	}
}
