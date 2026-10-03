package api

import (
	"context"
	"net/netip"
	"testing"

	thawrv1 "github.com/sira-labs/thawr/internal/api/proto/thawr/v1"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/wg"
)

const testOverlay6 = "fd3a:9c1e:44b0::/64"

// enrolIPv6 registers a peer whose client says it handles IPv6.
func (e *syncEnv) enrolIPv6(hostname string) *thawrv1.EnrollResponse {
	e.t.Helper()
	ctx := context.Background()
	tok, err := e.tokens.Create(ctx, e.admin, control.TokenRequest{OwnerName: "markus", Kind: "human"})
	if err != nil {
		e.t.Fatal(err)
	}
	key, _ := wg.GenerateKey()
	resp, err := e.client.Enroll(ctx, &thawrv1.EnrollRequest{Token: tok.Secret, PublicKey: key.PublicKey().String(), Hostname: hostname, ClientVersion: "0.2.0", Ipv6: true})
	if err != nil {
		e.t.Fatalf("enroll %s: %v", hostname, err)
	}
	return resp
}

func TestSyncIPv6Capability(t *testing.T) {
	env := newSyncEnv(t)
	oldID, oldSecret := env.enrol("old")
	resp := env.enrolIPv6("new")
	if resp.GetIpv6() == "" || resp.GetOverlayIpv6() != testOverlay6 {
		t.Fatalf("enroll with ipv6: ipv6 %q overlay %q", resp.GetIpv6(), resp.GetOverlayIpv6())
	}
	if want := control.IPv6For(netip.MustParsePrefix(testOverlay6), netip.MustParseAddr(resp.GetIpv4())).String(); resp.GetIpv6() != want {
		t.Errorf("ipv6 %s, want %s derived from %s", resp.GetIpv6(), want, resp.GetIpv4())
	}

	// The old client's map carries no IPv6 at all.
	oldStream, err := env.client.Sync(authCtx(oldSecret), &thawrv1.SyncRequest{ClientVersion: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	nm, err := recvMap(t, oldStream)
	if err != nil {
		t.Fatal(err)
	}
	if nm.GetSelf().GetIpv6() != "" || len(nm.GetHub().GetAllowedIps()) != 1 || len(nm.GetPeers()) != 1 || nm.GetPeers()[0].GetIpv6() != "" ||
		len(nm.GetPeers()[0].GetAllowedIps()) != 1 {
		t.Errorf("old client's map carries IPv6: %v", nm)
	}

	// The new client gets its own IPv6 and the hub's, but not the old
	// peer's, whose client never asked for it.
	newStream, err := env.client.Sync(authCtx(resp.GetNodeSecret()), &thawrv1.SyncRequest{ClientVersion: "0.2.0", Ipv6: true})
	if err != nil {
		t.Fatal(err)
	}
	nm, err = recvMap(t, newStream)
	if err != nil {
		t.Fatal(err)
	}
	if nm.GetSelf().GetIpv6() != resp.GetIpv6() || nm.GetSelf().GetOverlayIpv6() != testOverlay6 ||
		len(nm.GetHub().GetAllowedIps()) != 2 || nm.GetHub().GetAllowedIps()[1] != "fd3a:9c1e:44b0::6440:1/128" {
		t.Errorf("new client's self/hub: %v / %v", nm.GetSelf(), nm.GetHub())
	}
	if p := nm.GetPeers()[0]; p.GetId() != oldID || p.GetIpv6() != "" {
		t.Errorf("new client sees the old peer's IPv6: %v", p)
	}

	// Once the old peer's client asks for IPv6 too, the new client's map
	// carries its address.
	upgraded, err := env.client.Sync(authCtx(oldSecret), &thawrv1.SyncRequest{ClientVersion: "0.2.0", Ipv6: true})
	if err != nil {
		t.Fatal(err)
	}
	if nm, err = recvMap(t, upgraded); err != nil || nm.GetSelf().GetIpv6() == "" {
		t.Fatalf("upgraded client's map: %v %v", nm.GetSelf(), err)
	}
	for {
		nm, err = recvMap(t, newStream)
		if err != nil {
			t.Fatal(err)
		}
		if p := nm.GetPeers()[0]; p.GetIpv6() != "" {
			if len(p.GetAllowedIps()) != 2 || p.GetAllowedIps()[1] != p.GetIpv6()+"/128" {
				t.Errorf("upgraded peer's allowed ips: %v", p.GetAllowedIps())
			}
			break
		}
	}
}
