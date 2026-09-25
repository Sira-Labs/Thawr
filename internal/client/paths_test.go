package client

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/wg"
	"github.com/sira-labs/thawr/internal/wg/wgtest"
)

var (
	candLAN1 = netip.MustParseAddrPort("192.0.2.21:41820")
	candLAN2 = netip.MustParseAddrPort("192.0.2.20:41820")
	candRefl = netip.MustParseAddrPort("203.0.113.9:41820")
)

// endpointsOf lists, in order of appearance, the distinct endpoints the
// device saw for key.
func endpointsOf(fake *wgtest.Fake, key wg.Key) []netip.AddrPort {
	var out []netip.AddrPort
	for _, cfg := range fake.Snapshots() {
		for _, p := range cfg.Peers {
			if p.PublicKey == key && p.Endpoint.IsValid() && (len(out) == 0 || out[len(out)-1] != p.Endpoint) {
				out = append(out, p.Endpoint)
			}
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within 5s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// twoPeers enrols a (the daemon) and b (with reported candidates).
func twoPeers(t *testing.T, cp *controlPlane, cands []control.Endpoint, bSymmetric bool) (dirA string, stA, stB State, keyB wg.Key) {
	t.Helper()
	dirA, dirB := t.TempDir(), t.TempDir()
	stA = cp.enrol(dirA, "a")
	stB = cp.enrol(dirB, "b")
	k, err := LoadKey(dirB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cp.endpoints.Set(stB.PeerID, cands, bSymmetric, 41820); err != nil {
		t.Fatal(err)
	}
	return dirA, stA, stB, k.PublicKey()
}

func TestDaemonProbesOnIntent(t *testing.T) {
	cp := newControlPlane(t)
	cands := []control.Endpoint{{Addr: candLAN1, Kind: control.EndpointLocal}, {Addr: candLAN2, Kind: control.EndpointLocal}, {Addr: candRefl, Kind: control.EndpointReflexive}}
	dirA, stA, stB, keyB := twoPeers(t, cp, cands, false)
	var triggers atomic.Int32
	d, fake, stop := startDaemon(t, dirA, func(o *DaemonOptions) {
		o.Trigger = func(_ context.Context, iface string, src, dst netip.Addr) error {
			if iface != "thawr0" || src.String() != stA.IPv4 || dst.String() != stB.IPv4 {
				t.Errorf("trigger %s -> %s", src, dst)
			}
			triggers.Add(1)
			return nil
		}
	})
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return len(nm.Peers) == 1 })

	// Idle: b points at a loopback sink and nothing is probed.
	waitFor(t, "sink endpoint", func() bool {
		eps := endpointsOf(fake, keyB)
		return len(eps) == 1 && eps[0].Addr().IsLoopback()
	})
	time.Sleep(200 * time.Millisecond)
	if eps := endpointsOf(fake, keyB); len(eps) != 1 || triggers.Load() != 0 {
		t.Fatalf("idle peer was probed: %v triggers=%d", eps, triggers.Load())
	}
	lc := NewLocalClient(d.opts.Socket)
	st, err := lc.Status(context.Background())
	if err != nil || len(st.Peers) != 1 || st.Peers[0].Path != PathOffline || st.Peers[0].PathEndpoint != "" || len(st.NAT.Local) != 1 || len(st.NAT.Reflexive) != 1 || st.NAT.Reflexive[0] != "203.0.113.5:"+itoa(st.WireGuard.ListenPort) || st.NAT.Type != NATCone {
		t.Fatalf("idle status: %+v err=%v", st, err)
	}

	// The second candidate answers: the handshake advances while it is set.
	go func() {
		waitFor(t, "second probe", func() bool {
			eps := endpointsOf(fake, keyB)
			return len(eps) >= 3 && eps[2] == candLAN1
		})
		fake.SetStats(wg.PeerStats{PublicKey: keyB, Endpoint: candLAN1, LastHandshake: time.Now()})
	}()
	res, err := lc.Ping(context.Background(), "b")
	if err != nil || res.State != "direct" || res.Endpoint != candLAN1.String() || res.Peer != "b" {
		t.Fatalf("ping: %+v err=%v", res, err)
	}
	eps := endpointsOf(fake, keyB)
	if len(eps) != 3 || !eps[0].Addr().IsLoopback() || eps[1] != candLAN2 || eps[2] != candLAN1 {
		t.Fatalf("probe sequence: %v (same-/24 candidates first, sorted by address)", eps)
	}
	if n := triggers.Load(); n != 2 {
		t.Errorf("triggers = %d, want one per candidate", n)
	}
	st, _ = lc.Status(context.Background())
	if st.Peers[0].Path != "direct" || st.Peers[0].PathEndpoint != candLAN1.String() || st.Peers[0].Probes != 2 || len(st.Peers[0].EndpointCandidates) != 3 || st.Peers[0].EndpointCandidates[2].Kind != KindReflexive {
		t.Errorf("direct status: %+v", st.Peers[0])
	}
	waitFor(t, "path report on the server", func() bool {
		for _, p := range cp.paths.Get(stA.PeerID) {
			if p.PeerID == stB.PeerID && p.State == "direct" && p.Endpoint == candLAN1.String() {
				return true
			}
		}
		return false
	})
	if _, err := lc.Ping(context.Background(), "nobody"); err == nil {
		t.Error("ping of unknown peer succeeded")
	}
	// Our own reflexive candidate reached the server (port-preserving guess).
	waitFor(t, "reflexive endpoint reported", func() bool {
		eps, _ := cp.endpoints.Get(stA.PeerID)
		return len(eps) == 2 && eps[1].Kind == control.EndpointReflexive && eps[1].Addr.Port() == uint16(st.WireGuard.ListenPort)
	})
}

func TestDaemonSinkIntentStartsProbe(t *testing.T) {
	cp := newControlPlane(t)
	dirA, _, _, keyB := twoPeers(t, cp, []control.Endpoint{{Addr: candLAN2, Kind: control.EndpointLocal}}, false)
	d, fake, stop := startDaemon(t, dirA)
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return len(nm.Peers) == 1 })
	var sinkEP netip.AddrPort
	waitFor(t, "sink endpoint", func() bool {
		eps := endpointsOf(fake, keyB)
		if len(eps) == 1 {
			sinkEP = eps[0]
		}
		return len(eps) == 1
	})
	// WireGuard would send its handshake initiation here on queued traffic.
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(sinkEP))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(make([]byte, 148)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "probe after sink intent", func() bool {
		eps := endpointsOf(fake, keyB)
		return len(eps) == 2 && eps[1] == candLAN2
	})
	// No answer: the relay takes over (a loopback proxy, not the sink),
	// and one candidate is retried per RetryAfter, returning to the relay.
	lc := NewLocalClient(d.opts.Socket)
	waitFor(t, "relay", func() bool {
		st, _ := lc.Status(context.Background())
		return len(st.Peers) == 1 && st.Peers[0].Path == "relay" && st.Relay.Connected && st.Relay.Peers == 1
	})
	eps := endpointsOf(fake, keyB)
	if len(eps) != 3 || !eps[2].Addr().IsLoopback() || eps[2] == sinkEP {
		t.Fatalf("after exhaustion: %v (sink %s)", eps, sinkEP)
	}
	waitFor(t, "retry from relay", func() bool {
		eps := endpointsOf(fake, keyB)
		return len(eps) >= 5 && eps[3] == candLAN2 && eps[4].Addr().IsLoopback()
	})
	if st, _ := lc.Status(context.Background()); st.Peers[0].Path != "relay" || st.Peers[0].PathEndpoint != "" {
		t.Errorf("after retry: %+v", st.Peers[0])
	}
}

func TestDaemonSymmetricPeersUseRelay(t *testing.T) {
	cp := newControlPlane(t)
	dirA, stA, stB, keyB := twoPeers(t, cp, []control.Endpoint{{Addr: candRefl, Kind: control.EndpointReflexive}}, true)
	d, fake, stop := startDaemon(t, dirA, func(o *DaemonOptions) { o.STUN = fixedSTUN("203.0.113.5:4444", true) })
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return len(nm.Peers) == 1 && nm.Peers[0].Symmetric })
	lc := NewLocalClient(d.opts.Socket)
	waitFor(t, "own symmetric verdict", func() bool { st, _ := lc.Status(context.Background()); return st.NAT.Type == NATSymmetric })
	if st, _ := lc.Status(context.Background()); st.Relay.Connected {
		t.Fatal("relay connected before any peer needed it")
	}
	res, err := lc.Ping(context.Background(), "b")
	if err != nil || res.State != "relay" || res.Endpoint != "" {
		t.Fatalf("ping: %+v err=%v", res, err)
	}
	for _, ep := range endpointsOf(fake, keyB) {
		if !ep.Addr().IsLoopback() {
			t.Fatalf("reflexive candidate probed between two symmetric NATs: %s", ep)
		}
	}
	waitFor(t, "relay session on the server", func() bool {
		st, _ := lc.Status(context.Background())
		return st.Relay.Connected && st.Relay.Peers == 1 && cp.relay.Stats().Sessions == 1
	})
	waitFor(t, "relay reported", func() bool {
		for _, p := range cp.paths.Get(stA.PeerID) {
			if p.PeerID == stB.PeerID && p.State == "relay" {
				return true
			}
		}
		return false
	})
	// The peer reaches us directly from a public address: upgrade and
	// release the proxy.
	fake.SetStats(wg.PeerStats{PublicKey: keyB, Endpoint: candRefl, LastHandshake: time.Now()})
	waitFor(t, "direct via roaming", func() bool {
		st, _ := lc.Status(context.Background())
		return st.Peers[0].Path == "direct" && st.Peers[0].PathEndpoint == candRefl.String()
	})
	waitFor(t, "proxy released and connection idle", func() bool {
		st, _ := lc.Status(context.Background())
		return st.Relay.Peers == 0 && !st.Relay.Connected
	})
}

func TestEndpointReportDedup(t *testing.T) {
	t0 := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	a := endpointReport{ListenPort: 1, Endpoints: []control.Endpoint{{Addr: candLAN1, Kind: control.EndpointLocal}}}
	b := endpointReport{ListenPort: 1, Endpoints: []control.Endpoint{{Addr: candLAN2, Kind: control.EndpointLocal}}}
	sym := a
	sym.Symmetric = true
	cases := []struct {
		name     string
		prev     endpointReport
		lastSent time.Time
		now      time.Time
		want     bool
	}{
		{"first report", a, time.Time{}, t0, true},
		{"unchanged inside interval", a, t0, t0.Add(30 * time.Second), false},
		{"unchanged after interval", a, t0, t0.Add(60 * time.Second), true},
		{"changed candidates", b, t0, t0.Add(time.Second), true},
		{"changed symmetric", sym, t0, t0.Add(time.Second), true},
	}
	for _, tc := range cases {
		if got := shouldSend(tc.prev, a, tc.lastSent, tc.now, time.Minute); got != tc.want {
			t.Errorf("%s: shouldSend = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func itoa(n int) string { return netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(n)).String()[8:] }
