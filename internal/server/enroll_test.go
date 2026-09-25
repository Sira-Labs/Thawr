package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/sira-labs/thawr/internal/client"
)

// postLocal sends a JSON request over the admin socket.
func postLocal(t *testing.T, socket, method, path string, body any) (int, []byte) {
	t.Helper()
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	c := unixHTTPClient(socket)
	ctx, cancel := context.WithTimeout(context.Background(), 10e9)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://thawr"+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

// TestEnrollOverTLS is the spec's flow end to end: create a user and a
// token over the admin socket, enrol a client over pinned TLS+gRPC, and
// see the peer in the list. Nothing secret may reach the logs.
func TestEnrollOverTLS(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PublicAddr = "127.0.0.1"
	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)

	code, body := postLocal(t, cfg.AdminSocket, http.MethodPost, "/api/v1/users", map[string]string{"name": "alice", "role": "member", "password": "alicepassword"})
	if code != http.StatusCreated {
		t.Fatalf("create user: %d %s", code, body)
	}
	code, body = postLocal(t, cfg.AdminSocket, http.MethodPost, "/api/v1/tokens", map[string]any{"owner": "alice", "kind": "human", "tags": []string{"tag:dev"}})
	if code != http.StatusCreated {
		t.Fatalf("create token: %d %s", code, body)
	}
	var created struct {
		Secret      string `json:"secret"`
		JoinCommand string `json:"join_command"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(created.JoinCommand, "--server https://127.0.0.1:") || !strings.Contains(created.JoinCommand, "--fingerprint "+h.srv.tlsFingerprint) {
		t.Errorf("join command: %s", created.JoinCommand)
	}

	st, err := client.Enroll(context.Background(), client.Options{
		Server: "https://" + h.srv.HTTPSAddr(), Token: created.Secret, Fingerprint: h.srv.tlsFingerprint,
		StateDir: t.TempDir(), Hostname: "Alice Laptop", Version: "0.1.0",
	})
	if err != nil {
		t.Fatalf("client enroll: %v\nlogs:\n%s", err, h.logs.String())
	}
	if st.Name != "alice-laptop" || st.IPv4 != "100.64.0.2" || st.HubPublicKey != h.srv.hubKey.PublicKey().String() || st.OverlayCIDR != "100.64.0.0/10" {
		t.Errorf("enrolled state: %+v", st)
	}

	if _, err := client.Enroll(context.Background(), client.Options{
		Server: "https://" + h.srv.HTTPSAddr(), Token: created.Secret, Fingerprint: h.srv.tlsFingerprint, StateDir: t.TempDir(),
		Hostname: "second", Version: "0.1.0",
	}); err == nil || !strings.Contains(err.Error(), "invalid token") {
		t.Errorf("token reuse: %v", err)
	}

	code, body = postLocal(t, cfg.AdminSocket, http.MethodGet, "/api/v1/peers", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"name":"alice-laptop"`) || !strings.Contains(string(body), `"owner":"alice"`) {
		t.Errorf("peer list: %d %s", code, body)
	}
	code, body = postLocal(t, cfg.AdminSocket, http.MethodGet, "/api/v1/status", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"peer_count":1`) || !strings.Contains(string(body), `"netmap_generation":1`) {
		t.Errorf("status: %d %s", code, body)
	}
	if code, _ := postLocal(t, cfg.AdminSocket, http.MethodDelete, "/api/v1/peers/alice-laptop", nil); code != http.StatusNoContent {
		t.Errorf("delete peer: %d", code)
	}

	logs := h.logs.String()
	for _, secret := range []string{created.Secret, st.NodeSecret, "alicepassword"} {
		if strings.Contains(logs, secret) {
			t.Errorf("secret material in logs: %q", secret[:6])
		}
	}
	for _, want := range []string{"user created", "token created", "peer enrolled", "peer deleted"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %q", want)
		}
	}
}

func TestPublicURL(t *testing.T) {
	cfg, _ := testConfig(t)
	cases := map[[2]string]string{
		{"vpn.example.com", ":443"}:       "https://vpn.example.com",
		{"vpn.example.com", ":8443"}:      "https://vpn.example.com:8443",
		{"vpn.example.com:9443", ":8443"}: "https://vpn.example.com:9443",
		{"10.0.0.1", "0.0.0.0:443"}:       "https://10.0.0.1",
	}
	for in, want := range cases {
		cfg.PublicAddr, cfg.Listen.HTTPS = in[0], in[1]
		s := &Server{cfg: cfg}
		if got := s.publicURL(); got != want {
			t.Errorf("publicURL(%v) = %q, want %q", in, got, want)
		}
	}
}
