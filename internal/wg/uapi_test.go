package wg

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRenderUAPI(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := peer.PublicKey()
	cfg := Config{
		PrivateKey: priv,
		ListenPort: 51820,
		Peers: []Peer{{
			PublicKey:  pub,
			Endpoint:   netip.MustParseAddrPort("203.0.113.5:41820"),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.7/32")},
			Keepalive:  25 * time.Second,
		}, {
			PublicKey:  peer,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.8/32"), netip.MustParsePrefix("100.64.0.9/32")},
		}},
	}
	gone, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	got := renderUAPI(cfg, []Key{gone})
	want := strings.Join([]string{
		"private_key=" + hex.EncodeToString(priv[:]),
		"listen_port=51820",
		"fwmark=0",
		"public_key=" + hex.EncodeToString(gone[:]),
		"remove=true",
		"public_key=" + hex.EncodeToString(pub[:]),
		"endpoint=203.0.113.5:41820",
		"replace_allowed_ips=true",
		"allowed_ip=100.64.0.7/32",
		"persistent_keepalive_interval=25",
		"public_key=" + hex.EncodeToString(peer[:]),
		"replace_allowed_ips=true",
		"allowed_ip=100.64.0.8/32",
		"allowed_ip=100.64.0.9/32",
		"persistent_keepalive_interval=0",
		"",
	}, "\n")
	if got != want {
		t.Errorf("renderUAPI mismatch:\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestParseUAPIStats(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	out := strings.Join([]string{
		"private_key=00",
		"listen_port=51820",
		"public_key=" + hex.EncodeToString(k1[:]),
		"endpoint=203.0.113.5:41820",
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=500",
		"rx_bytes=1234",
		"tx_bytes=99",
		"public_key=" + hex.EncodeToString(k2[:]),
		"last_handshake_time_sec=0",
		"last_handshake_time_nsec=0",
		"rx_bytes=0",
		"tx_bytes=0",
		"errno=0",
		"",
	}, "\n")
	stats, err := parseUAPIStats(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("got %d peers, want 2", len(stats))
	}
	s := stats[0]
	if s.PublicKey != k1 || s.Endpoint.String() != "203.0.113.5:41820" || s.RxBytes != 1234 || s.TxBytes != 99 {
		t.Errorf("peer 1 mismatch: %+v", s)
	}
	if !s.LastHandshake.Equal(time.Unix(1700000000, 500)) {
		t.Errorf("handshake: %v", s.LastHandshake)
	}
	if !stats[1].LastHandshake.IsZero() {
		t.Errorf("peer 2 should have zero handshake, got %v", stats[1].LastHandshake)
	}
}

func TestParseUAPIStatsErrno(t *testing.T) {
	if _, err := parseUAPIStats("errno=1\n"); err == nil {
		t.Fatal("expected error for errno=1")
	}
}

func TestFingerprint(t *testing.T) {
	k, _ := GenerateKey()
	fp := Fingerprint(k)
	if len(fp) != 8 {
		t.Errorf("fingerprint length %d, want 8", len(fp))
	}
	if strings.Contains(k.String(), fp) {
		t.Errorf("fingerprint must not be a substring of the key")
	}
}

func TestParseKey(t *testing.T) {
	k, _ := GenerateKey()
	back, err := ParseKey(k.String())
	if err != nil || back != k {
		t.Errorf("round trip failed: %v", err)
	}
	if _, err := ParseKey("nope"); err == nil {
		t.Error("expected error for invalid key")
	}
}
