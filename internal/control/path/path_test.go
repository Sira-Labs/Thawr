package path

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/control"
)

func ep(s string, k control.EndpointKind) control.Endpoint {
	return control.Endpoint{Addr: netip.MustParseAddrPort(s), Kind: k}
}

func TestCandidateOrdering(t *testing.T) {
	ours := []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("10.0.0.5")}
	cases := []struct {
		name          string
		theirs        []control.Endpoint
		self, peerSym bool
		want          []string
	}{
		{"lan first, then local, reflexive, stable",
			[]control.Endpoint{ep("203.0.113.9:4000", control.EndpointReflexive), ep("172.16.0.2:4000", control.EndpointLocal),
				ep("192.168.1.20:4000", control.EndpointLocal), ep("198.51.100.1:51820", control.EndpointStable)},
			false, false,
			[]string{"192.168.1.20:4000", "172.16.0.2:4000", "203.0.113.9:4000", "198.51.100.1:51820"}},
		{"ties by address string",
			[]control.Endpoint{ep("192.168.1.30:4000", control.EndpointLocal), ep("192.168.1.20:4000", control.EndpointLocal)},
			false, false, []string{"192.168.1.20:4000", "192.168.1.30:4000"}},
		{"both symmetric skips reflexive",
			[]control.Endpoint{ep("203.0.113.9:4000", control.EndpointReflexive), ep("192.168.1.20:4000", control.EndpointLocal)},
			true, true, []string{"192.168.1.20:4000"}},
		{"one symmetric keeps reflexive",
			[]control.Endpoint{ep("203.0.113.9:4000", control.EndpointReflexive)},
			true, false, []string{"203.0.113.9:4000"}},
		{"duplicates and unknown kinds dropped",
			[]control.Endpoint{ep("192.168.1.20:4000", control.EndpointLocal), ep("192.168.1.20:4000", control.EndpointLocal), {Addr: netip.MustParseAddrPort("1.2.3.4:5")}},
			false, false, []string{"192.168.1.20:4000"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Order(ours, tc.theirs, tc.self, tc.peerSym)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i].String() != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
	// Both sides compute the same relative order for symmetric inputs.
	a := Order(ours, []control.Endpoint{ep("192.168.1.20:1", control.EndpointLocal), ep("203.0.113.9:1", control.EndpointReflexive)}, false, false)
	b := Order([]netip.Addr{netip.MustParseAddr("192.168.1.20")}, []control.Endpoint{ep("192.168.1.10:1", control.EndpointLocal), ep("203.0.113.8:1", control.EndpointReflexive)}, false, false)
	if a[0].Addr().Is4() != b[0].Addr().Is4() || !a[0].Addr().IsPrivate() || !b[0].Addr().IsPrivate() {
		t.Errorf("sides disagree on class order: %v vs %v", a, b)
	}
}

var (
	c1 = netip.MustParseAddrPort("192.168.1.20:4000")
	c2 = netip.MustParseAddrPort("203.0.113.9:4000")
)

func TestPathStateMachine(t *testing.T) {
	t0 := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) time.Time { return t0.Add(d) }

	t.Run("idle without intent", func(t *testing.T) {
		m := New(Options{})
		m.SetCandidates([]netip.AddrPort{c1})
		out := m.Step(Input{Now: t0})
		if out.Action != ActSink || out.State != Idle {
			t.Fatalf("first step: %+v", out)
		}
		for i := 1; i < 100; i++ {
			if out := m.Step(Input{Now: at(time.Duration(i) * time.Second)}); out.Action != ActNone || out.State != Idle {
				t.Fatalf("tick %d: %+v", i, out)
			}
		}
		if m.Probes() != 0 {
			t.Fatal("idle peer was probed")
		}
	})

	t.Run("second candidate wins", func(t *testing.T) {
		m := New(Options{})
		m.SetCandidates([]netip.AddrPort{c1, c2})
		m.Step(Input{Now: t0})
		out := m.Step(Input{Now: at(100 * time.Millisecond), Intent: true})
		if out.Action != ActProbe || out.Endpoint != c1 || out.State != Probing || !out.Changed {
			t.Fatalf("probe 1: %+v", out)
		}
		if out := m.Step(Input{Now: at(1 * time.Second)}); out.Action != ActNone {
			t.Fatalf("within window: %+v", out)
		}
		out = m.Step(Input{Now: at(2200 * time.Millisecond)})
		if out.Action != ActProbe || out.Endpoint != c2 {
			t.Fatalf("probe 2: %+v", out)
		}
		out = m.Step(Input{Now: at(2700 * time.Millisecond), Handshake: at(2600 * time.Millisecond), Endpoint: c2})
		if out.State != Direct || out.Endpoint != c2 || !out.Changed || out.Action != ActNone {
			t.Fatalf("direct: %+v", out)
		}
		if out := m.Step(Input{Now: at(3 * time.Second), Handshake: at(2600 * time.Millisecond), Endpoint: c2}); out.Changed {
			t.Fatalf("spurious change: %+v", out)
		}
	})

	t.Run("exhaustion and retry", func(t *testing.T) {
		m := New(Options{})
		m.SetCandidates([]netip.AddrPort{c1, c2})
		m.Step(Input{Now: t0})
		m.Step(Input{Now: t0, Intent: true})
		m.Step(Input{Now: at(2 * time.Second)})
		out := m.Step(Input{Now: at(4 * time.Second)})
		if out.State != Unreachable || out.Action != ActSink || out.Endpoint.IsValid() || !out.Changed {
			t.Fatalf("exhausted: %+v", out)
		}
		if m.Probes() != 2 {
			t.Fatalf("probes = %d, want 2", m.Probes())
		}
		// Fresh intent inside RetryAfter does not restart.
		for d := 5 * time.Second; d < 60*time.Second; d += 5 * time.Second {
			if out := m.Step(Input{Now: at(d), Intent: true}); out.Action != ActNone {
				t.Fatalf("premature retry at %s: %+v", d, out)
			}
		}
		out = m.Step(Input{Now: at(61 * time.Second), Intent: true})
		if out.Action != ActProbe || out.Endpoint != c1 {
			t.Fatalf("retry: %+v", out)
		}
	})

	t.Run("peer reaches us first", func(t *testing.T) {
		m := New(Options{})
		m.SetCandidates([]netip.AddrPort{c1})
		m.Step(Input{Now: t0})
		learned := netip.MustParseAddrPort("203.0.113.7:5555")
		out := m.Step(Input{Now: at(time.Second), Handshake: at(time.Second), Endpoint: learned})
		if out.State != Direct || out.Endpoint != learned || out.Action != ActNone {
			t.Fatalf("roamed: %+v", out)
		}
		// Roaming while direct follows the device.
		moved := netip.MustParseAddrPort("203.0.113.7:6666")
		out = m.Step(Input{Now: at(2 * time.Second), Handshake: at(2 * time.Second), Endpoint: moved})
		if out.Endpoint != moved || !out.Changed {
			t.Fatalf("roam update: %+v", out)
		}
	})

	t.Run("stalled direct path re-probes", func(t *testing.T) {
		m := New(Options{})
		m.SetCandidates([]netip.AddrPort{c1})
		m.Step(Input{Now: t0})
		m.Step(Input{Now: t0, Intent: true})
		m.Step(Input{Now: at(time.Second), Handshake: at(time.Second), Endpoint: c1, Rx: 10, Tx: 10})
		// Traffic keeps flowing: no stall even after 3 min.
		out := m.Step(Input{Now: at(4 * time.Minute), Handshake: at(time.Second), Endpoint: c1, Rx: 20, Tx: 20})
		if out.State != Direct {
			t.Fatalf("healthy path re-probed: %+v", out)
		}
		out = m.Step(Input{Now: at(5 * time.Minute), Handshake: at(time.Second), Endpoint: c1, Rx: 20, Tx: 30})
		if out.State != Probing || out.Action != ActProbe {
			t.Fatalf("stall not detected: %+v", out)
		}
	})

	t.Run("candidate change re-probes an unreachable peer", func(t *testing.T) {
		m := New(Options{})
		m.SetCandidates(nil)
		m.Step(Input{Now: t0})
		out := m.Step(Input{Now: t0, Intent: true})
		if out.State != Unreachable || m.Probes() != 0 {
			t.Fatalf("empty list: %+v probes=%d", out, m.Probes())
		}
		m.SetCandidates([]netip.AddrPort{c2})
		out = m.Step(Input{Now: at(3 * time.Second)})
		if out.Action != ActProbe || out.Endpoint != c2 {
			t.Fatalf("after candidates: %+v", out)
		}
	})

	t.Run("probe rate stays under one per window", func(t *testing.T) {
		m := New(Options{})
		m.SetCandidates([]netip.AddrPort{c1, c2})
		m.Step(Input{Now: t0})
		probes := 0
		for i := 0; i < 400; i++ {
			out := m.Step(Input{Now: at(time.Duration(i) * 50 * time.Millisecond), Intent: true})
			if out.Action == ActProbe {
				probes++
			}
		}
		// 20 s of constant intent: one round of two probes, no retry yet.
		if probes != 2 {
			t.Fatalf("probes in 20 s = %d", probes)
		}
	})
}

func TestPathRelayUpgrade(t *testing.T) {
	t0 := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) time.Time { return t0.Add(d) }

	t.Run("exhaustion ends in relay and retries one candidate per period", func(t *testing.T) {
		m := New(Options{Relay: true})
		m.SetCandidates([]netip.AddrPort{c1, c2})
		m.Step(Input{Now: t0})
		m.Step(Input{Now: t0, Intent: true})
		m.Step(Input{Now: at(2 * time.Second)})
		out := m.Step(Input{Now: at(4 * time.Second)})
		if out.State != Relay || out.Action != ActRelay || out.Endpoint.IsValid() || !out.Changed {
			t.Fatalf("after exhaustion: %+v", out)
		}
		if out := m.Step(Input{Now: at(30 * time.Second), Intent: true}); out.Action != ActNone || out.State != Relay {
			t.Fatalf("early retry: %+v", out)
		}
		// A rekey through the relay reports a loopback-free zero endpoint
		// (the daemon masks the proxy address) and must not look direct.
		if out := m.Step(Input{Now: at(40 * time.Second), Handshake: at(40 * time.Second)}); out.State != Relay {
			t.Fatalf("relay rekey looked direct: %+v", out)
		}
		out = m.Step(Input{Now: at(65 * time.Second)})
		if out.Action != ActProbe || out.Endpoint != c1 || out.State != Probing {
			t.Fatalf("first retry: %+v", out)
		}
		out = m.Step(Input{Now: at(67*time.Second + 100*time.Millisecond)})
		if out.State != Relay || out.Action != ActRelay {
			t.Fatalf("back to relay: %+v", out)
		}
		out = m.Step(Input{Now: at(128 * time.Second)})
		if out.Action != ActProbe || out.Endpoint != c2 {
			t.Fatalf("second retry uses the next candidate: %+v", out)
		}
		// This retry succeeds.
		out = m.Step(Input{Now: at(129 * time.Second), Handshake: at(129 * time.Second), Endpoint: c2})
		if out.State != Direct || out.Endpoint != c2 {
			t.Fatalf("upgrade: %+v", out)
		}
		if m.Probes() != 4 {
			t.Errorf("probes = %d", m.Probes())
		}
	})

	t.Run("peer reaches us while relayed", func(t *testing.T) {
		m := New(Options{Relay: true})
		m.SetCandidates(nil)
		m.Step(Input{Now: t0})
		if out := m.Step(Input{Now: t0, Intent: true}); out.State != Relay || m.Probes() != 0 {
			t.Fatalf("empty list: %+v", out)
		}
		learned := netip.MustParseAddrPort("203.0.113.7:5555")
		out := m.Step(Input{Now: at(time.Second), Handshake: at(time.Second), Endpoint: learned})
		if out.State != Direct || out.Endpoint != learned || !out.Changed {
			t.Fatalf("roamed from relay: %+v", out)
		}
		// Without candidates the relay never retries.
		m2 := New(Options{Relay: true})
		m2.Step(Input{Now: t0})
		m2.Step(Input{Now: t0, Intent: true})
		for d := time.Minute; d < 10*time.Minute; d += time.Minute {
			if out := m2.Step(Input{Now: at(d)}); out.Action != ActNone {
				t.Fatalf("retry without candidates: %+v", out)
			}
		}
	})

	t.Run("candidate change starts a full round from the relay", func(t *testing.T) {
		m := New(Options{Relay: true})
		m.SetCandidates([]netip.AddrPort{c1})
		m.Step(Input{Now: t0})
		m.Step(Input{Now: t0, Intent: true})
		if out := m.Step(Input{Now: at(2 * time.Second)}); out.State != Relay {
			t.Fatalf("relay: %+v", out)
		}
		m.SetCandidates([]netip.AddrPort{c2, c1})
		out := m.Step(Input{Now: at(5 * time.Second)})
		if out.Action != ActProbe || out.Endpoint != c2 {
			t.Fatalf("round after change: %+v", out)
		}
		out = m.Step(Input{Now: at(7 * time.Second)})
		if out.Action != ActProbe || out.Endpoint != c1 {
			t.Fatalf("second candidate of the round: %+v", out)
		}
		out = m.Step(Input{Now: at(9 * time.Second)})
		if out.State != Relay || out.Action != ActRelay {
			t.Fatalf("round exhausted: %+v", out)
		}
	})

	t.Run("direct stall falls back to relay", func(t *testing.T) {
		m := New(Options{Relay: true})
		m.SetCandidates([]netip.AddrPort{c1})
		m.Step(Input{Now: t0})
		m.Step(Input{Now: t0, Intent: true})
		m.Step(Input{Now: at(time.Second), Handshake: at(time.Second), Endpoint: c1, Rx: 1, Tx: 1})
		out := m.Step(Input{Now: at(5 * time.Minute), Handshake: at(time.Second), Endpoint: c1, Rx: 1, Tx: 9})
		if out.State != Probing {
			t.Fatalf("stall: %+v", out)
		}
		out = m.Step(Input{Now: at(5*time.Minute + 3*time.Second)})
		if out.State != Relay || out.Action != ActRelay {
			t.Fatalf("relay after stall: %+v", out)
		}
	})
}
