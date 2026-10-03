package server

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/wg"
	"github.com/sira-labs/thawr/internal/wg/wgtest"
)

// TestSyncIPv6Upgrade enrols a device as a client from before spec 015
// would (no IPv6 flag), then runs an upgraded daemon on it: the server
// marks it capable, the netmap carries its IPv6 address and a capable
// peer's, the device gets both addresses and state.json keeps them.
func TestSyncIPv6Upgrade(t *testing.T) {
	cfg, _ := testConfig(t)
	allowSelfPolicy(t, cfg)
	cfg.Overlay.IPv6 = "fd3a:9c1e:44b0::/64"
	h := newHarness(t, cfg)
	h.srv.deps.HubOptions = control.HubOptions{Coalesce: 10 * time.Millisecond}
	h.start(t)
	defer h.stop(t)

	server := "https://" + h.srv.HTTPSAddr()
	dirA, dirB := t.TempDir(), t.TempDir()
	enroll := func(dir, host string, ipv6 bool) client.State {
		st, err := client.Enroll(context.Background(), client.Options{Server: server, Token: createTokenLocal(t, cfg.AdminSocket), Fingerprint: h.srv.tlsFingerprint,
			StateDir: dir, Hostname: host, Version: "0.1.0", IPv6: func() bool { return ipv6 }})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	a := enroll(dirA, "a", false)
	b := enroll(dirB, "b", true)
	if a.IPv6 != "" || b.IPv6 != "fd3a:9c1e:44b0::6440:3" || b.OverlayIPv6 != "fd3a:9c1e:44b0::/64" {
		t.Fatalf("enrolled states: a %q, b %q %q", a.IPv6, b.IPv6, b.OverlayIPv6)
	}

	fake := wgtest.New("thawr1")
	d, err := client.NewDaemon(client.DaemonOptions{
		StateDir: dirA, Socket: filepath.Join(shortTempDir(t), "c.sock"), Interface: "thawr1",
		OpenDevice: func(context.Context, wg.Options) (wg.Device, error) { return fake, nil },
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "0.1.0", MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond,
		IPv6: func() bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	}()

	want6 := "fd3a:9c1e:44b0::6440:2"
	var got client.NetMap
	waitUntil(t, "netmap with IPv6", func() bool {
		select {
		case got = <-d.Applied():
			return got.SelfIPv6 == want6 && len(got.Peers) == 1 && got.Peers[0].IPv6 == b.IPv6
		default:
			return false
		}
	})
	if got.Overlay6 != "fd3a:9c1e:44b0::/64" {
		t.Errorf("overlay6 %q", got.Overlay6)
	}
	last, _ := fake.Last()
	if !slices.Contains(last.Addresses, netip.MustParsePrefix(want6+"/64")) {
		t.Errorf("device addresses %v lack %s/64", last.Addresses, want6)
	}
	waitUntil(t, "state.json keeps the IPv6 address", func() bool {
		st, err := client.LoadState(dirA)
		return err == nil && st.IPv6 == want6 && st.OverlayIPv6 == "fd3a:9c1e:44b0::/64"
	})
	// The hub routes the upgraded device's /128 now.
	waitUntil(t, "hub /128 for a", func() bool {
		last, _ := h.fake.Last()
		for _, p := range last.Peers {
			if slices.Contains(p.AllowedIPs, netip.MustParsePrefix(want6+"/128")) {
				return true
			}
		}
		return false
	})
}
