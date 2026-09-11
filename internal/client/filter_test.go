package client

import (
	"context"
	"net/netip"
	"testing"

	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/store"
	"github.com/thedatadudech/thawr/internal/wg"
)

// ruleVisibility is the same-owner rule plus one fixed filter rule, so
// the daemon test can watch rules travel through the netmap.
type ruleVisibility struct{ control.OwnerVisibility }

func (ruleVisibility) FilterFor(store.Peer) []control.FilterRule {
	return []control.FilterRule{{SrcIPv4: netip.MustParseAddr("100.64.0.99"), Proto: "tcp", PortLo: 22, PortHi: 22}}
}

func TestDaemonInstallsFilter(t *testing.T) {
	cp := newControlPlane(t, func(o *cpOptions) { o.visibility = ruleVisibility{} })
	dirA, stA, stB, _ := twoPeers(t, cp, nil, false)
	d, fake, stop := startDaemon(t, dirA)
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return len(nm.Peers) == 1 })
	set, ok := fake.LastFilter()
	if !ok {
		t.Fatal("no filter installed")
	}
	if set.Hook != wg.HookInput || set.Interface != "thawr0" || set.Local.String() != stA.IPv4 {
		t.Errorf("filter set: %+v", set)
	}
	if len(set.Rules) != 1 || set.Rules[0].Src.String() != "100.64.0.99/32" || set.Rules[0].Proto != "tcp" || set.Rules[0].Lo != 22 {
		t.Errorf("rules: %+v", set.Rules)
	}
	wantVisible := map[string]bool{stB.IPv4: true, "100.64.0.1": true}
	for _, v := range set.Visible {
		delete(wantVisible, v.String())
	}
	if len(wantVisible) != 0 {
		t.Errorf("visible set lacks %v (got %v)", wantVisible, set.Visible)
	}
	fake.SetDrops(3)
	st, err := NewLocalClient(d.opts.Socket).Status(context.Background())
	if err != nil || st.Filter == nil || st.Filter.Rules != 1 || st.Filter.Drops != 3 || st.Filter.Dropped5m != 3 {
		t.Fatalf("status filter: %+v err=%v", st.Filter, err)
	}
	// The cached netmap carries the filter too.
	nm, ok, err := loadNetMapSettled(dirA)
	if err != nil || !ok || len(nm.Filter) != 1 || nm.Filter[0].Src != "100.64.0.99" {
		t.Errorf("cached filter: %+v ok=%v err=%v", nm.Filter, ok, err)
	}
}
