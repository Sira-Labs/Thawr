package config

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func noEnv(string) string { return "" }

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte("public_addr: vpn.example.com\n"), noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := Default()
	want.PublicAddr = "vpn.example.com"
	checks := []struct{ name, got, want string }{
		{"data_dir", cfg.DataDir, want.DataDir},
		{"listen.https", cfg.Listen.HTTPS, want.Listen.HTTPS},
		{"listen.wireguard", cfg.Listen.WireGuard, want.Listen.WireGuard},
		{"listen.stun", strings.Join(cfg.Listen.STUN, ","), strings.Join(want.Listen.STUN, ",")},
		{"overlay.cidr", cfg.Overlay.CIDR, want.Overlay.CIDR},
		{"overlay.interface", cfg.Overlay.Interface, want.Overlay.Interface},
		{"overlay.interface default", DefaultInterface(), map[bool]string{true: "utun", false: "thawr0"}[runtime.GOOS == "darwin"]},
		{"tls.mode", cfg.TLS.Mode, TLSModeSelfSigned},
		{"policy_file", cfg.PolicyFile, want.PolicyFile},
		{"admin_socket", cfg.AdminSocket, filepath.Join(DefaultDataDir, "admin.sock")},
		{"log.level", cfg.Log.Level, "info"},
		{"log.format", cfg.Log.Format, "text"},
		{"min_client_version", cfg.MinClientVersion, ""},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestAdminSocketFollowsDataDir(t *testing.T) {
	cfg, err := Parse([]byte("public_addr: vpn.example.com\ndata_dir: /srv/thawr\n"), noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := cfg.AdminSocket, filepath.Join("/srv/thawr", "admin.sock"); got != want {
		t.Errorf("admin_socket: got %q, want %q", got, want)
	}
}

func TestDerivedValues(t *testing.T) {
	cfg, err := Parse([]byte("public_addr: vpn.example.com:8443\n"), noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.PublicHost(); got != "vpn.example.com" {
		t.Errorf("PublicHost: %q", got)
	}
	if got, want := cfg.HubAddr(), netip.MustParsePrefix("100.64.0.1/10"); got != want {
		t.Errorf("HubAddr: got %s, want %s", got, want)
	}
	if got := cfg.STUNEndpoints(); len(got) != 2 || got[0] != "vpn.example.com:3478" || got[1] != "vpn.example.com:3479" {
		t.Errorf("STUNEndpoints = %v", got)
	}
	if got := cfg.HubEndpoint(); got != "vpn.example.com:51820" {
		t.Errorf("HubEndpoint: %q", got)
	}
	if got, want := cfg.OverlayPrefix(), netip.MustParsePrefix("100.64.0.0/10"); got != want {
		t.Errorf("OverlayPrefix: got %s, want %s", got, want)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string // substrings that must appear in the error
	}{
		{"missing public_addr", "data_dir: /tmp/x\n", []string{"public_addr: required"}},
		{"bad public port", "public_addr: 'vpn:abc'\n", []string{"public_addr: port"}},
		{"bad cidr", "public_addr: a\noverlay:\n  cidr: nope\n", []string{"overlay.cidr"}},
		{"ipv6 cidr", "public_addr: a\noverlay:\n  cidr: fd00::/64\n", []string{"only IPv4"}},
		{"tiny cidr", "public_addr: a\noverlay:\n  cidr: 10.0.0.0/31\n", []string{"/30 or larger"}},
		{"long interface", "public_addr: a\noverlay:\n  interface: abcdefghijklmnopq\n", []string{"overlay.interface"}},
		{"bad listen", "public_addr: a\nlisten:\n  https: '443'\n", []string{"listen.https"}},
		{"bad metrics listen", "public_addr: a\nmetrics:\n  listen: localhost\n", []string{"metrics.listen"}},
		{"no stun", "public_addr: a\nlisten:\n  stun: []\n", []string{"listen.stun: at least one"}},
		{"negative relay limit", "public_addr: a\nrelay:\n  max_bytes_per_second: -1\n", []string{"relay.max_bytes_per_second"}},
		{"three stun", "public_addr: a\nlisten:\n  stun: [':1', ':2', ':3']\n", []string{"at most two"}},
		{"tls file without files", "public_addr: a\ntls:\n  mode: file\n", []string{"tls.cert_file", "tls.key_file"}},
		{"tls bad mode", "public_addr: a\ntls:\n  mode: letsencrypt\n", []string{"tls.mode"}},
		{"acme without email", "public_addr: vpn.example.org\ntls:\n  mode: acme\n", []string{"tls.email: required"}},
		{"acme bad email", "public_addr: vpn.example.org\ntls:\n  mode: acme\n  email: 'Ops <ops@example.org>'\n", []string{"tls.email"}},
		{"acme ip public_addr", "public_addr: 203.0.113.7\ntls:\n  mode: acme\n  email: ops@example.org\n", []string{"tls.mode acme needs a DNS name"}},
		{"acme ip domain", "public_addr: vpn.example.org\ntls:\n  mode: acme\n  email: ops@example.org\n  domain: 203.0.113.7\n", []string{"tls.domain"}},
		{"acme pinned name", "public_addr: vpn.example.org\ntls:\n  mode: acme\n  email: ops@example.org\n  domain: Thawr-Pinned.INVALID\n", []string{"reserved .invalid"}},
		{"acme invalid public_addr", "public_addr: vpn.invalid\ntls:\n  mode: acme\n  email: ops@example.org\n", []string{"reserved .invalid"}},
		{"acme single label", "public_addr: vpn\ntls:\n  mode: acme\n  email: ops@example.org\n", []string{"tls.domain"}},
		{"acme http directory", "public_addr: vpn.example.org\ntls:\n  mode: acme\n  email: ops@example.org\n  acme_directory: http://ca.example/dir\n", []string{"tls.acme_directory"}},
		{"bad log level", "public_addr: a\nlog:\n  level: loud\n", []string{"log.level"}},
		{"bad log format", "public_addr: a\nlog:\n  format: xml\n", []string{"log.format"}},
		{"bad min version", "public_addr: a\nmin_client_version: v1\n", []string{"min_client_version"}},
		{"unknown key", "public_addr: a\nbogus: 1\n", []string{"bogus"}},
		{"bad dns upstream", "public_addr: a\ndns:\n  upstream: ['1.1.1.1', 'dns.example']\n", []string{"dns.upstream[1]"}},
		{"dns upstream port zero", "public_addr: a\ndns:\n  upstream: ['1.1.1.1:0']\n", []string{"dns.upstream[0]"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml), noEnv)
			if err == nil {
				t.Fatal("expected error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err.Error(), w)
				}
			}
		})
	}
}

func TestACMEConfig(t *testing.T) {
	cases := []struct {
		name, yaml, domain string
		warn               bool
	}{
		{"https not on 443", "public_addr: vpn.example.org\nmin_client_version: '0.2'\nlisten:\n  https: ':8443'\ntls:\n  mode: acme\n  email: ops@example.org\n", "vpn.example.org", true},
		{"domain from public_addr", "public_addr: vpn.example.org:443\ntls:\n  mode: acme\n  email: ops@example.org\n", "vpn.example.org", true},
		{"domain beside an ip", "public_addr: 203.0.113.7\ntls:\n  mode: acme\n  email: ops@example.org\n  domain: vpn.example.org\n  acme_directory: https://acme-staging-v02.api.letsencrypt.org/directory\n", "vpn.example.org", true},
		{"old clients excluded", "public_addr: vpn.example.org\nmin_client_version: '0.2'\ntls:\n  mode: acme\n  email: ops@example.org\n", "vpn.example.org", false},
		{"newer minimum", "public_addr: vpn.example.org\nmin_client_version: '1.0'\ntls:\n  mode: acme\n  email: ops@example.org\n", "vpn.example.org", false},
		{"self-signed never warns", "public_addr: vpn.example.org\n", "vpn.example.org", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tc.yaml), noEnv)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := cfg.ACMEDomain(); got != tc.domain {
				t.Errorf("ACMEDomain = %q, want %q", got, tc.domain)
			}
			if w := cfg.Warnings(); (len(w) > 0) != tc.warn {
				t.Errorf("Warnings = %q, want warning %v", w, tc.warn)
			}
		})
	}
}

func TestValidateCollectsAllProblems(t *testing.T) {
	_, err := Parse([]byte("overlay:\n  cidr: nope\nlog:\n  level: loud\n"), noEnv)
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("got %T, want *ValidationError", err)
	}
	if len(verr.Problems) != 3 {
		t.Errorf("got %d problems, want 3: %v", len(verr.Problems), verr.Problems)
	}
}

func TestEnvOverride(t *testing.T) {
	env := func(k string) string {
		if k == EnvLogLevel {
			return "debug"
		}
		return ""
	}
	cfg, err := Parse([]byte("public_addr: a\nlog:\n  level: warn\n"), noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Log.Level != "warn" {
		t.Fatalf("file value not applied: %q", cfg.Log.Level)
	}
	cfg, err = Parse([]byte("public_addr: a\nlog:\n  level: warn\n"), env)
	if err != nil {
		t.Fatalf("Parse with env: %v", err)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("env override: got %q, want debug", cfg.Log.Level)
	}
}

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config", "server.example.yaml"))
	if err != nil {
		t.Fatalf("Load example: %v", err)
	}
	if cfg.PublicAddr != "vpn.example.com" {
		t.Errorf("public_addr: %q", cfg.PublicAddr)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("got %v, want ErrNotExist", err)
	}
}

func TestDNSConfig(t *testing.T) {
	cfg, err := Parse([]byte("public_addr: a\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DNS.Enabled || len(cfg.DNSUpstreams()) != 0 {
		t.Errorf("defaults: %+v", cfg.DNS)
	}
	cfg, err = Parse([]byte("public_addr: a\ndns:\n  enabled: false\n  upstream: ['1.1.1.1', '[2606:4700::1111]:5353', '9.9.9.9:53']\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	ups := cfg.DNSUpstreams()
	if cfg.DNS.Enabled || len(ups) != 3 || ups[0].String() != "1.1.1.1:53" || ups[1].String() != "[2606:4700::1111]:5353" || ups[2].Port() != 53 {
		t.Errorf("upstreams: enabled=%v %v", cfg.DNS.Enabled, ups)
	}
}

func TestAuditConfig(t *testing.T) {
	cfg, err := Parse([]byte("public_addr: a\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.RetentionDays != DefaultAuditRetentionDays {
		t.Errorf("default retention: %d", cfg.Audit.RetentionDays)
	}
	cfg, err = Parse([]byte("public_addr: a\naudit:\n  retention_days: 0\n"), noEnv)
	if err != nil || cfg.Audit.RetentionDays != 0 {
		t.Errorf("zero retention: %+v %v", cfg.Audit, err)
	}
	if _, err := Parse([]byte("public_addr: a\naudit:\n  retention_days: -1\n"), noEnv); err == nil || !strings.Contains(err.Error(), "audit.retention_days") {
		t.Errorf("negative retention accepted: %v", err)
	}
	if cfg, err := Parse([]byte("public_addr: a\naudit:\n  retention_days: 106751\n"), noEnv); err != nil || cfg.Audit.RetentionDays != MaxAuditRetentionDays {
		t.Errorf("maximum retention rejected: %v", err)
	}
	if _, err := Parse([]byte("public_addr: a\naudit:\n  retention_days: 106752\n"), noEnv); err == nil || !strings.Contains(err.Error(), "exceeds the maximum") {
		t.Errorf("overflowing retention accepted: %v", err)
	}
}

func TestParseResolvConf(t *testing.T) {
	in := `# Generated by NetworkManager
search lan example.org
nameserver 192.168.1.1   # router
nameserver 127.0.0.53
; another comment
nameserver fe80::1%eth0
nameserver not-an-ip
options timeout:2 attempts:3
`
	got := ParseResolvConf(strings.NewReader(in))
	want := []string{"192.168.1.1:53", "127.0.0.53:53", "[fe80::1]:53"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("[%d] %s, want %s", i, got[i], want[i])
		}
	}
	if ParseResolvConf(strings.NewReader("")) != nil {
		t.Error("empty input yields entries")
	}
}
