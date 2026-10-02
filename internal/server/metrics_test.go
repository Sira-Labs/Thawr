package server

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/store"
)

func TestMetricsScrape(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.Metrics.Listen = "127.0.0.1:0"
	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)
	ctx := context.Background()

	const secret = "secret-host-name"
	if err := h.srv.st.Peers().Create(ctx, store.Peer{ID: "p1", Name: secret, Kind: store.KindAgent, Mode: store.ModeAgent,
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", IPv4: "100.64.0.77", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.users.Authenticate(ctx, "nobody", "wrong password"); err == nil {
		t.Fatal("login with a wrong password succeeded")
	}

	code, body := adminGet(t, cfg.AdminSocket, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("socket /metrics: %d %s", code, body)
	}
	scrape := string(body)
	for _, want := range []string{
		`thawr_build_info{version="test"} 1`,
		`thawr_peers{kind="agent"} 1`,
		`thawr_peers{kind="human"} 0`,
		`thawr_peers{kind="server"} 0`,
		"thawr_peers_online 0",
		"# TYPE thawr_netmap_generation gauge",
		"thawr_relay_sessions 0",
		"# TYPE thawr_relay_bytes_total counter",
		`thawr_stun_requests_total{result="ok"} 0`,
		`thawr_stun_requests_total{result="ratelimited"} 0`,
		`thawr_stun_requests_total{result="malformed"} 0`,
		"thawr_login_failures_total 1",
		"# TYPE thawr_audit_rows gauge",
		"# TYPE thawr_uptime_seconds gauge",
	} {
		if !strings.Contains(scrape, want) {
			t.Errorf("scrape lacks %q", want)
		}
	}
	for _, leak := range []string{secret, "100.64.0.77", "AAAAAAAA", "nobody", h.srv.tlsFingerprint, h.srv.hubKey.PublicKey().String()} {
		if strings.Contains(scrape, leak) {
			t.Errorf("scrape leaks %q", leak)
		}
	}

	addr := h.srv.MetricsAddr()
	if addr == "" {
		t.Fatal("metrics listener not bound")
	}
	get := func(url string) (int, string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if c, b := get("http://" + addr + "/metrics"); c != http.StatusOK || !strings.Contains(b, `thawr_peers{kind="agent"} 1`) {
		t.Errorf("tcp /metrics: %d %q", c, b)
	}
	for _, p := range []string{"/", "/api/v1/status", "/api/v1/backup"} {
		if c, _ := get("http://" + addr + p); c != http.StatusNotFound {
			t.Errorf("tcp %s: %d, want 404", p, c)
		}
	}

	// The HTTPS listener does not serve metrics.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+h.srv.HTTPSAddr()+"/metrics", nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(b), "thawr_peers") {
		t.Errorf("HTTPS serves metrics: %d", resp.StatusCode)
	}
}

func TestMetricsListenerOff(t *testing.T) {
	cfg, _ := testConfig(t)
	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)
	if addr := h.srv.MetricsAddr(); addr != "" {
		t.Errorf("metrics listener bound at %s without metrics.listen", addr)
	}
	if code, _ := adminGet(t, cfg.AdminSocket, "/metrics"); code != http.StatusOK {
		t.Errorf("socket /metrics: %d", code)
	}
}
