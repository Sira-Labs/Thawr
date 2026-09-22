package client

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/thedatadudech/thawr/internal/wg"
)

const routesTestPolicy = `version: 1
acls:
  - action: accept
    src: [alice]
    dst: ["10.1.0.0/24:22"]
  - action: accept
    src: [bob]
    dst: ["internet:*"]
`

// TestDaemonRoutes walks spec 013 against the fake device: the gateway
// advertises, approval makes the route appear on alice's device and the
// forward rules on the gateway, bob selects the exit node, a revoke
// takes the route away.
func TestDaemonRoutes(t *testing.T) {
	cp := newControlPlane(t, func(o *cpOptions) { o.policy, o.users = routesTestPolicy, []string{"alice", "bob"} })
	ctx := context.Background()
	dirGW, dirA, dirB := t.TempDir(), t.TempDir(), t.TempDir()
	gwState := cp.enrol(dirGW, "gw")
	gwState.AdvertiseRoutes = []string{"10.1.0.0/24", "0.0.0.0/0"}
	if err := SaveState(dirGW, gwState); err != nil {
		t.Fatal(err)
	}
	cp.enrolOwned(dirA, "alice-laptop", "alice", nil)
	cp.enrolOwned(dirB, "bob-box", "bob", nil)

	gw, fakeGW, stopGW := startDaemon(t, dirGW)
	defer stopGW()
	lcGW := NewLocalClient(gw.opts.Socket)
	// Advertised and pending: nobody sees the gateway yet.
	stGW := waitStatus(t, lcGW, "gateway advertised", func(s Status) bool { return len(s.Advertised) == 2 })
	if stGW.Advertised[0].Approved || stGW.Advertised[1].Approved || len(stGW.Peers) != 0 {
		t.Fatalf("gateway before approval: %+v peers %d", stGW.Advertised, len(stGW.Peers))
	}
	a, fakeA, stopA := startDaemon(t, dirA)
	defer stopA()
	b, fakeB, stopB := startDaemon(t, dirB)
	defer stopB()
	lcA, lcB := NewLocalClient(a.opts.Socket), NewLocalClient(b.opts.Socket)
	waitApplied(t, a, func(nm NetMap) bool { return nm.Generation > 0 })
	if st, _ := lcA.Status(ctx); len(st.Peers) != 0 || len(st.Routes) != 0 {
		t.Fatalf("alice before approval: peers %+v routes %+v", st.Peers, st.Routes)
	}

	for _, p := range []string{"10.1.0.0/24", "0.0.0.0/0"} {
		if err := cp.routes.SetApproved(ctx, cp.admin, "gw", p, true); err != nil {
			t.Fatal(err)
		}
	}
	// Alice routes the subnet through the gateway; the OS route and the
	// AllowedIP follow.
	stA := waitStatus(t, lcA, "alice route", func(s Status) bool { return len(s.Routes) == 1 })
	if stA.Routes[0].Prefix != "10.1.0.0/24" || stA.Routes[0].Via != "gw" || stA.ExitNode.State != ExitStateOff {
		t.Errorf("alice status: %+v exit %+v", stA.Routes, stA.ExitNode)
	}
	if got := fakeA.LastRoutes(); len(got) != 1 || got[0].String() != "10.1.0.0/24" {
		t.Errorf("alice OS routes: %v", got)
	}
	if cfg, ok := fakeA.Last(); !ok || len(cfg.Peers) != 2 || cfg.FwMark != 0 {
		t.Errorf("alice config: %+v", cfg)
	}
	// Alice may not use the exit node.
	if _, err := lcA.SetExitNode(ctx, "gw"); err == nil {
		t.Error("alice selected an exit node the policy denies")
	} else if le := new(LocalError); !errors.As(err, &le) || le.Status != http.StatusNotFound {
		t.Errorf("alice exit node error: %v", err)
	}
	// Bob sees the gateway as exit node and has no subnet route.
	stB := waitStatus(t, lcB, "bob sees gw", func(s Status) bool { return len(s.Peers) == 1 })
	if len(stB.Routes) != 0 || stB.ExitNode.State != ExitStateOff {
		t.Errorf("bob before selection: %+v", stB)
	}
	res, err := lcB.SetExitNode(ctx, "gw")
	if err != nil || res.Name != "gw" || res.State != ExitStateActive {
		t.Fatalf("bob exit node: %+v %v", res, err)
	}
	cfg, _ := fakeB.Last()
	var gwPeer *wg.Peer
	for i := range cfg.Peers {
		for _, ip := range cfg.Peers[i].AllowedIPs {
			if ip == wg.ExitRoute {
				gwPeer = &cfg.Peers[i]
			}
		}
	}
	if gwPeer == nil || cfg.FwMark != wg.DefaultFwMark {
		t.Fatalf("bob config after selection: %+v", cfg)
	}
	if got := fakeB.LastRoutes(); len(got) != 1 || got[0] != wg.ExitRoute {
		t.Errorf("bob OS routes: %v", got)
	}
	if st, _ := LoadState(dirB); st.ExitNode != "gw" {
		t.Errorf("exit node not persisted: %+v", st)
	}
	stB, _ = lcB.Status(ctx)
	if len(stB.Routes) != 1 || stB.Routes[0].Prefix != "0.0.0.0/0" || stB.ExitNode.State != ExitStateActive {
		t.Errorf("bob status with exit node: %+v %+v", stB.Routes, stB.ExitNode)
	}
	if res, err := lcB.SetExitNode(ctx, ExitNodeOff); err != nil || res.State != ExitStateOff {
		t.Fatalf("exit node off: %+v %v", res, err)
	}
	if cfg, _ := fakeB.Last(); cfg.FwMark != 0 || len(fakeB.LastRoutes()) != 0 {
		t.Errorf("bob config after off: %+v routes %v", cfg, fakeB.LastRoutes())
	}

	// The gateway enforces both grants on its forwarding path and
	// masquerades what it advertised.
	stGW = waitStatus(t, lcGW, "gateway sees both", func(s Status) bool { return len(s.Peers) == 2 })
	if !stGW.Advertised[0].Approved || !stGW.Advertised[1].Approved {
		t.Errorf("gateway advertised after approval: %+v", stGW.Advertised)
	}
	set, ok := fakeGW.LastFilter()
	if !ok || len(set.Forward) != 2 || len(set.Masquerade) != 2 || !set.MasqueradeFrom.IsValid() || len(set.Rules) != 0 {
		t.Fatalf("gateway filter: %+v", set)
	}
	for _, f := range set.Forward {
		switch f.Dst.String() {
		case "10.1.0.0/24":
			if f.Lo != 22 || f.Hi != 22 {
				t.Errorf("subnet forward rule: %+v", f)
			}
		case "0.0.0.0/0":
			if f.Lo != 1 || f.Hi != 65535 {
				t.Errorf("exit forward rule: %+v", f)
			}
		default:
			t.Errorf("unexpected forward rule: %+v", f)
		}
	}
	if len(fakeGW.LastRoutes()) != 0 {
		t.Errorf("gateway installed routes for itself: %v", fakeGW.LastRoutes())
	}

	// Revoking the subnet takes the route out of alice's device.
	if err := cp.routes.SetApproved(ctx, cp.admin, "gw", "10.1.0.0/24", false); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, lcA, "alice route gone", func(s Status) bool { return len(s.Routes) == 0 && len(s.Peers) == 0 })
	if got := fakeA.LastRoutes(); len(got) != 0 {
		t.Errorf("alice OS routes after revoke: %v", got)
	}
}

// TestFilterSetForServesOnlyAdvertised checks that forward rules the
// server sends for prefixes this device never advertised are dropped.
func TestFilterSetForServesOnlyAdvertised(t *testing.T) {
	nm := NetMap{Forward: []ForwardRule{
		{Src: "100.64.0.3", Dst: "10.1.0.0/24", Proto: "any", PortLo: 22, PortHi: 22},
		{Src: "100.64.0.3", Dst: "10.9.0.0/24", Proto: "any", PortLo: 1, PortHi: 65535},
		{Src: "100.64.0.4", Dst: "0.0.0.0/0", Proto: "any", PortLo: 1, PortHi: 65535},
	}}
	overlay := netip.MustParsePrefix("100.64.0.0/10")
	set := FilterSetFor(nm, "thawr0", netip.MustParseAddr("100.64.0.2"), overlay, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/24")})
	if len(set.Forward) != 1 || set.Forward[0].Dst.String() != "10.1.0.0/24" {
		t.Errorf("forward rules: %+v", set.Forward)
	}
	if len(set.Masquerade) != 1 || set.MasqueradeFrom != overlay {
		t.Errorf("masquerade: %v from %v", set.Masquerade, set.MasqueradeFrom)
	}
	if plain := FilterSetFor(nm, "thawr0", netip.MustParseAddr("100.64.0.2"), overlay, nil); len(plain.Forward) != 0 || len(plain.Masquerade) != 0 {
		t.Errorf("plain client got router rules: %+v", plain)
	}
}
