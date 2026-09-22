package control

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/thedatadudech/thawr/internal/control/policy"
	"github.com/thedatadudech/thawr/internal/store"
)

type routesEnv struct {
	*enrollEnv
	svc    *RoutesService
	policy *PolicyService
	// gw advertises routes; laptop and box are plain peers of alice and
	// bob; alice's rule grants the subnet, bob's the internet.
	gw, laptop, box store.Peer
}

const routesPolicy = `version: 1
acls:
  - action: accept
    src: [alice]
    dst: ["10.1.0.0/24:22"]
  - action: accept
    src: [bob]
    dst: ["internet:*"]
`

func newRoutesEnv(t *testing.T) *routesEnv {
	t.Helper()
	env := newEnrollEnv(t, "100.64.0.0/10")
	overlay := netip.MustParsePrefix("100.64.0.0/10")
	a := NewAuditor(env.clk.Now)
	mustUser(t, env.users, "alice", store.RoleMember)
	mustUser(t, env.users, "bob", store.RoleMember)
	gw, err := env.enroll(t, env.token(t, TokenRequest{}), "gw")
	if err != nil {
		t.Fatal(err)
	}
	laptop, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "laptop")
	if err != nil {
		t.Fatal(err)
	}
	box, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "bob"}), "box")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(routesPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := NewPolicyService(env.st, quietLogger(), path, nil).WithOverlay(overlay)
	if err := ps.LoadInitial(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc := NewRoutesService(env.st, quietLogger(), env.clk.Now, overlay).WithAuditor(a)
	return &routesEnv{enrollEnv: env, svc: svc, policy: ps, gw: gw.Peer, laptop: laptop.Peer, box: box.Peer}
}

func (e *routesEnv) actions(t *testing.T, action string) int {
	t.Helper()
	rows, err := e.st.Audit().List(context.Background(), store.AuditQuery{Action: action, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func TestAdvertiseRoutesReplacesSet(t *testing.T) {
	env := newRoutesEnv(t)
	ctx := context.Background()
	gen0, _ := env.st.Meta().Generation(ctx)
	rows, err := env.svc.Advertise(ctx, env.gw, []string{"10.1.0.0/24", "0.0.0.0/0"})
	if err != nil || len(rows) != 2 || rows[0].Approved || rows[1].Approved {
		t.Fatalf("advertise: %+v %v", rows, err)
	}
	if n := env.actions(t, AuditRouteAdvertise); n != 2 {
		t.Errorf("route.advertise rows: %d", n)
	}
	gen1, _ := env.st.Meta().Generation(ctx)
	if gen1 != gen0+1 {
		t.Errorf("generation %d -> %d", gen0, gen1)
	}
	// The same set again: no audit row, no generation bump.
	if _, err := env.svc.Advertise(ctx, env.gw, []string{"0.0.0.0/0", "10.1.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	if gen2, _ := env.st.Meta().Generation(ctx); gen2 != gen1 || env.actions(t, AuditRouteAdvertise) != 2 {
		t.Error("unchanged set bumped the generation or was audited")
	}
	if err := env.svc.SetApproved(ctx, env.admin, "gw", "10.1.0.0/24", true); err != nil {
		t.Fatal(err)
	}
	// Withdrawing drops the approval; re-advertising needs a new one.
	if _, err := env.svc.Advertise(ctx, env.gw, []string{"0.0.0.0/0"}); err != nil {
		t.Fatal(err)
	}
	if n := env.actions(t, AuditRouteWithdraw); n != 1 {
		t.Errorf("route.withdraw rows: %d", n)
	}
	rows, _ = env.svc.Advertise(ctx, env.gw, []string{"0.0.0.0/0", "10.1.0.0/24"})
	for _, r := range rows {
		if r.Approved {
			t.Errorf("approval survived a withdraw: %+v", r)
		}
	}
	// Validation: overlay overlap, non-canonical, duplicates, too many,
	// IPv6, and a static peer.
	bad := [][]string{{"100.64.1.0/24"}, {"10.1.0.5/24"}, {"10.1.0.0/24", "10.1.0.0/24"}, {"fd00::/64"}, {"nonsense"}}
	for _, b := range bad {
		if _, err := env.svc.Advertise(ctx, env.gw, b); !errors.Is(err, ErrValidation) {
			t.Errorf("%v accepted: %v", b, err)
		}
	}
	many := make([]string, MaxAdvertisedRoutes+1)
	for i := range many {
		many[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16).String()
	}
	if _, err := env.svc.Advertise(ctx, env.gw, many); !errors.Is(err, ErrValidation) {
		t.Errorf("%d routes accepted: %v", len(many), err)
	}
	if _, err := env.svc.Advertise(ctx, store.Peer{ID: "phone", Name: "phone", Mode: store.ModeStatic}, []string{"10.5.0.0/24"}); !errors.Is(err, ErrForbidden) {
		t.Errorf("static peer advertised: %v", err)
	}
}

func TestApproveRequiresAdvertised(t *testing.T) {
	env := newRoutesEnv(t)
	ctx := context.Background()
	if err := env.svc.SetApproved(ctx, env.admin, "gw", "10.1.0.0/24", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("approve of an unadvertised prefix: %v", err)
	}
	if err := env.svc.SetApproved(ctx, env.admin, "nobody", "10.1.0.0/24", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("approve on an unknown peer: %v", err)
	}
	if _, err := env.svc.Advertise(ctx, env.gw, []string{"10.1.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	member := Principal{UserID: env.laptop.OwnerID, Name: "alice", Role: store.RoleMember}
	if err := env.svc.SetApproved(ctx, member, "gw", "10.1.0.0/24", true); !errors.Is(err, ErrForbidden) {
		t.Errorf("member approved: %v", err)
	}
	if err := env.svc.SetApproved(ctx, env.admin, "gw", "10.1.0.0/24", true); err != nil {
		t.Fatal(err)
	}
	rows, err := env.svc.List(ctx, env.admin, "gw")
	if err != nil || len(rows) != 1 || !rows[0].Approved || rows[0].ApprovedBy != env.admin.Name {
		t.Fatalf("list: %+v %v", rows, err)
	}
	if _, err := env.svc.List(ctx, member, "gw"); !errors.Is(err, ErrNotFound) {
		t.Errorf("member listed another owner's peer: %v", err)
	}
	if err := env.svc.SetApproved(ctx, env.admin, "gw", "10.1.0.0/24", false); err != nil {
		t.Fatal(err)
	}
	if rows, _ = env.svc.List(ctx, env.admin, "gw"); rows[0].Approved {
		t.Error("revoke kept the approval")
	}
	if env.actions(t, AuditRouteApprove) != 1 || env.actions(t, AuditRouteRevoke) != 1 {
		t.Error("approve and revoke not audited once each")
	}
}

func TestNetMapCarriesRoutes(t *testing.T) {
	env := newRoutesEnv(t)
	ctx := context.Background()
	hub := HubConfig{PublicKey: "HUBKEY", Endpoint: "vpn.example.com:51820", Address: netip.MustParseAddr("100.64.0.1"), Overlay: netip.MustParsePrefix("100.64.0.0/10")}
	b := NewNetMapBuilder(env.st, PolicyVisibility{Load: env.policy.Load}, nil, nil, hub, func() int64 { return 1 })
	if _, err := env.svc.Advertise(ctx, env.gw, []string{"10.1.0.0/24", "0.0.0.0/0"}); err != nil {
		t.Fatal(err)
	}
	// Unapproved: nobody sees the gateway, the gateway sees its pending
	// advertisement.
	nm, err := b.Build(ctx, env.laptop.ID)
	if err != nil || len(nm.Peers) != 0 {
		t.Fatalf("laptop before approval: %+v %v", nm.Peers, err)
	}
	nm, _ = b.Build(ctx, env.gw.ID)
	if len(nm.SelfAdvertised) != 2 || nm.SelfAdvertised[0].Approved || len(nm.Forward) != 0 {
		t.Errorf("gateway before approval: %+v forward %v", nm.SelfAdvertised, nm.Forward)
	}
	for _, p := range []string{"10.1.0.0/24", "0.0.0.0/0"} {
		if err := env.svc.SetApproved(ctx, env.admin, "gw", p, true); err != nil {
			t.Fatal(err)
		}
	}
	// Alice's laptop routes the subnet through the gateway and may not use
	// it as exit node; bob's box may, and gets no subnet route.
	nm, _ = b.Build(ctx, env.laptop.ID)
	if len(nm.Peers) != 1 || nm.Peers[0].ID != env.gw.ID || nm.Peers[0].ExitNode {
		t.Fatalf("laptop peers: %+v", nm.Peers)
	}
	if got := nm.Peers[0].AllowedIPs; len(got) != 2 || got[0] != netip.PrefixFrom(netip.MustParseAddr(env.gw.IPv4), 32) || got[1].String() != "10.1.0.0/24" {
		t.Errorf("laptop allowed ips: %v", got)
	}
	nm, _ = b.Build(ctx, env.box.ID)
	if len(nm.Peers) != 1 || !nm.Peers[0].ExitNode || len(nm.Peers[0].AllowedIPs) != 1 {
		t.Errorf("box peers: %+v", nm.Peers)
	}
	// The gateway sees both and installs one forward rule each.
	nm, _ = b.Build(ctx, env.gw.ID)
	if len(nm.Peers) != 2 || len(nm.Filter) != 0 {
		t.Errorf("gateway peers %d filter %v", len(nm.Peers), nm.Filter)
	}
	if len(nm.Forward) != 2 {
		t.Fatalf("gateway forward rules: %+v", nm.Forward)
	}
	byDst := map[string]ForwardRule{}
	for _, f := range nm.Forward {
		byDst[f.Dst.String()] = f
	}
	if f := byDst["10.1.0.0/24"]; f.SrcIPv4.String() != env.laptop.IPv4 || f.PortLo != 22 || f.PortHi != 22 {
		t.Errorf("subnet forward rule: %+v", f)
	}
	if f := byDst["0.0.0.0/0"]; f.SrcIPv4.String() != env.box.IPv4 || f.PortLo != 1 || f.PortHi != 65535 {
		t.Errorf("exit forward rule: %+v", f)
	}
	if !nm.SelfAdvertised[0].Approved || !nm.SelfAdvertised[1].Approved {
		t.Errorf("gateway advertised: %+v", nm.SelfAdvertised)
	}
}

// TestNetMapBuildUsesOneCompilation: a policy recompiled while a map is
// being built (an approval landing between two loads) must not yield a
// map that mixes both compilations, such as the gateway visible from the
// newer one without the exit-node flag the older one lacked.
func TestNetMapBuildUsesOneCompilation(t *testing.T) {
	env := newRoutesEnv(t)
	ctx := context.Background()
	if _, err := env.svc.Advertise(ctx, env.gw, []string{"0.0.0.0/0"}); err != nil {
		t.Fatal(err)
	}
	before := env.policy.Load()
	if err := env.svc.SetApproved(ctx, env.admin, "gw", "0.0.0.0/0", true); err != nil {
		t.Fatal(err)
	}
	after := env.policy.Load()
	// The first load of a build sees the old compilation, every later
	// one the new: a build that loads more than once mixes them.
	loads := 0
	load := func() *policy.Compiled {
		loads++
		if loads == 1 {
			return before
		}
		return after
	}
	hub := HubConfig{PublicKey: "HUBKEY", Address: netip.MustParseAddr("100.64.0.1"), Overlay: netip.MustParsePrefix("100.64.0.0/10")}
	b := NewNetMapBuilder(env.st, PolicyVisibility{Load: load}, nil, nil, hub, func() int64 { return 1 })
	nm, err := b.Build(ctx, env.box.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 0 {
		t.Fatalf("box map mixed two compilations: %+v", nm.Peers)
	}
	nm, err = b.Build(ctx, env.box.ID)
	if err != nil || len(nm.Peers) != 1 || !nm.Peers[0].ExitNode {
		t.Fatalf("box map from the new compilation: %+v %v", nm.Peers, err)
	}
}
