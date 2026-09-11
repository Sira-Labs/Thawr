package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/thedatadudech/thawr/internal/client"
)

// statusFixture mirrors the example in docs/specs/007-cli-status.md.
func statusFixture() client.Status {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	at := func(ago time.Duration) *time.Time { t := now.Add(-ago); return &t }
	return client.Status{
		Version: "0.1.0",
		Self:    client.SelfStatus{Name: "alice-laptop", PeerID: "p1", IPv4: "100.64.0.7", Kind: "human"},
		Server: client.ServerStatus{Addr: "vpn.example.com:8443", State: client.ServerConnected, Generation: 42,
			LastMessageAt: at(3 * time.Second), Version: "v0.1.0"},
		WireGuard: client.WGStatus{Backend: "kernel", Interface: "thawr0", ListenPort: 41820},
		NAT:       client.NATStatus{Type: client.NATCone, Reflexive: []string{"203.0.113.9:41820"}, Local: []string{"192.168.1.20:41820"}},
		Relay:     client.RelayStatus{Connected: true, Peers: 1},
		Filter:    &client.FilterStatus{Rules: 3, Drops: 12, Dropped5m: 0, Flows: 2},
		DNS:       &client.DNSStatus{Listen: "100.64.0.7:53", State: client.DNSServing, Method: "resolved", Names: 6},
		Hub: &client.PeerStatus{Name: "hub", IPv4: "100.64.0.1", Kind: "server", Online: true, PublicKey: "HUB=", Path: "direct",
			PathEndpoint: "vpn.example.com:51820", EndpointCandidates: []client.Candidate{}, LastHandshakeAt: at(25 * time.Second), RxBytes: 4000, TxBytes: 4200},
		Peers: []client.PeerStatus{
			{Name: "homelab-nas", IPv4: "100.64.0.3", Kind: "server", Online: true, PublicKey: "NAS=", Path: "direct", PathEndpoint: "198.51.100.4:51820",
				Probes: 1, EndpointCandidates: []client.Candidate{{Addr: "198.51.100.4:51820", Kind: "reflexive"}}, LastHandshakeAt: at(12 * time.Second), RxBytes: 1_234_000, TxBytes: 340_000},
			{Name: "build-box", IPv4: "100.64.0.9", Kind: "agent", Online: true, PublicKey: "BLD=", Path: "relay",
				Probes: 3, EndpointCandidates: []client.Candidate{{Addr: "10.0.0.5:41820", Kind: "local"}}, LastHandshakeAt: at(3 * time.Minute)},
			{Name: "alice-phone", IPv4: "100.64.0.21", Kind: "human", Owner: "alice", Online: false, PublicKey: "PHN=", Path: client.PathHub,
				EndpointCandidates: []client.Candidate{}},
			{Name: "bob-laptop", IPv4: "100.64.0.12", Kind: "human", Owner: "bob", Online: true, PublicKey: "BOB=", Path: "idle",
				EndpointCandidates: []client.Candidate{}},
		},
		Held:        []client.HeldStatus{},
		Lock:        client.LockStatus{Signers: []client.LockSignerStatus{}},
		RetrievedAt: now,
	}
}

func TestStatusRender(t *testing.T) {
	var out bytes.Buffer
	if err := renderStatus(&out, statusFixture()); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "status.golden")
	if os.Getenv("THAWR_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (set THAWR_UPDATE_GOLDEN=1 to create it): %v", err)
	}
	// A checkout with CRLF conversion must not fail the comparison.
	if got, want := out.String(), strings.ReplaceAll(string(want), "\r\n", "\n"); got != want {
		t.Errorf("render differs from %s:\n--- got ---\n%s--- want ---\n%s", golden, got, want)
	}
	for _, want := range []string{"connected (netmap #42, 3s ago)", "NAT: cone (reflexive 203.0.113.9:41820)", "direct 198.51.100.4:51820", "1.2 MB / 340 kB", "via hub", "never", "3 rules · 0 dropped (last 5 min)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

func TestStatusServerVersionHint(t *testing.T) {
	for _, tc := range []struct{ server, client, want string }{
		{"", "0.1.0", "server vpn.example.com:8443 connected"},
		{"v0.1.3", "0.1.0", "server vpn.example.com:8443 v0.1.3 connected"},
		{"v0.2.0", "0.1.0", "server vpn.example.com:8443 v0.2.0 (client update available) connected"},
		{"v0.2.0", "dev", "server vpn.example.com:8443 v0.2.0 connected"},
	} {
		st := statusFixture()
		st.Server.Version, st.Version = tc.server, tc.client
		var buf bytes.Buffer
		if err := renderStatus(&buf, st); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), tc.want) {
			t.Errorf("server %q client %q: header %q lacks %q", tc.server, tc.client, strings.SplitN(buf.String(), "\n", 2)[0], tc.want)
		}
	}
}

func TestStatusDNSLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		dns  *client.DNSStatus
		want string
	}{
		{"off", nil, "NAT: cone (reflexive 203.0.113.9:41820) · lock: off\n"},
		{"registered", &client.DNSStatus{Listen: "100.64.0.7:53", State: client.DNSServing, Method: "hosts", Names: 3}, "· DNS: .thawr via hosts · lock: off\n"},
		{"serve only", &client.DNSStatus{Listen: "100.64.0.7:53", State: client.DNSServing, Method: "none"}, "· DNS: serving, not registered · lock: off\n"},
		{"registration failed", &client.DNSStatus{Listen: "100.64.0.7:53", State: client.DNSServing, Method: "none", Error: "resolvectl: exit 1"}, "· DNS: serving, not registered (resolvectl: exit 1) · lock: off\n"},
		{"bind failed", &client.DNSStatus{Listen: "100.64.0.7:53", State: client.DNSError, Error: "address in use"}, "· DNS: error (address in use) · lock: off\n"},
	} {
		st := statusFixture()
		st.DNS = tc.dns
		var buf bytes.Buffer
		if err := renderStatus(&buf, st); err != nil {
			t.Fatal(err)
		}
		line := strings.SplitN(buf.String(), "\n", 3)[1] + "\n"
		if !strings.HasSuffix(line, tc.want) {
			t.Errorf("%s: line %q lacks %q", tc.name, line, tc.want)
		}
	}
}

func TestStatusRenderLongNames(t *testing.T) {
	st := statusFixture()
	long := strings.Repeat("abcde", 5) // 25 runes
	st.Peers[0].Name = long
	var out bytes.Buffer
	if err := renderStatus(&out, st); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out.String(), "\n")
	var table []string
	for i, l := range lines {
		if strings.HasPrefix(l, "PEER") {
			table = lines[i : i+6]
			break
		}
	}
	if len(table) != 6 {
		t.Fatalf("table rows: %d\n%s", len(table), out.String())
	}
	if strings.Contains(out.String(), long) || !strings.Contains(out.String(), long[:19]+"…") {
		t.Errorf("name not truncated: %s", table[1])
	}
	// Columns align on runes (the ellipsis is three bytes).
	col := func(l, s string) int { return utf8.RuneCountInString(l[:strings.Index(l, s)]) }
	ipCol := col(table[0], "IP")
	for _, l := range table[1:] {
		if idx := col(l, "100.64.0."); idx != ipCol {
			t.Errorf("IP column at %d, want %d: %q", idx, ipCol, l)
		}
	}
}

func TestStatusServerStates(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	next, since, old := now.Add(8*time.Second), now.Add(-2*time.Hour), now.Add(-30*time.Hour)
	cases := []struct {
		s    client.ServerStatus
		want string
	}{
		{client.ServerStatus{State: client.ServerConnected, Generation: 7, LastMessageAt: &since}, "connected (netmap #7, 2h ago)"},
		{client.ServerStatus{State: client.ServerReconnecting, Attempt: 3, NextRetryAt: &next}, "reconnecting (attempt 3, next in 8s)"},
		{client.ServerStatus{State: client.ServerCached, Attempt: 3, NextRetryAt: &next, UnreachableSince: &since}, "cached netmap (server unreachable since 10:00; attempt 3, next in 8s)"},
		{client.ServerStatus{State: client.ServerCached, Attempt: 1, UnreachableSince: &old}, "cached netmap (server unreachable since Sep 3 06:00; attempt 1, retrying now)"},
	}
	for _, tc := range cases {
		if got := serverState(tc.s, now); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.s.State, got, tc.want)
		}
	}
}

func TestHumanizeBytes(t *testing.T) {
	cases := map[uint64]string{0: "0 B", 999: "999 B", 1000: "1 kB", 4000: "4 kB", 340_000: "340 kB", 1_234_000: "1.2 MB", 1_260_000: "1.3 MB", 5_000_000_000: "5 GB", 1_500_000_000_000: "1.5 TB"}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("%d: got %q, want %q", n, got, want)
		}
	}
}

func TestHumanizeDuration(t *testing.T) {
	cases := map[time.Duration]string{-time.Second: "0s", 0: "0s", 12 * time.Second: "12s", 59 * time.Second: "59s", 3 * time.Minute: "3m", 119 * time.Minute: "1h", 2 * time.Hour: "2h", 5 * 24 * time.Hour: "5d"}
	for d, want := range cases {
		if got := humanDuration(d); got != want {
			t.Errorf("%v: got %q, want %q", d, got, want)
		}
	}
}

func TestStatusJSONSchema(t *testing.T) {
	schemaFile, err := os.Open(filepath.Join("..", "..", "docs", "status.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = schemaFile.Close() }()
	doc, err := jsonschema.UnmarshalJSON(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("status.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("status.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	validate := func(name string, st client.Status) {
		t.Helper()
		data, err := json.Marshal(st)
		if err != nil {
			t.Fatal(err)
		}
		v, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if err := sch.Validate(v); err != nil {
			t.Errorf("%s does not validate: %v\n%s", name, err, data)
		}
		if strings.Contains(string(data), "node_secret") || strings.Contains(string(data), "private_key") {
			t.Errorf("%s leaks secrets: %s", name, data)
		}
	}
	validate("fixture", statusFixture())
	minimal := client.Status{Server: client.ServerStatus{State: client.ServerReconnecting}, Peers: []client.PeerStatus{}, Held: []client.HeldStatus{},
		Lock: client.LockStatus{Signers: []client.LockSignerStatus{}},
		NAT:  client.NATStatus{Type: client.NATUnknown, Reflexive: []string{}, Local: []string{}}}
	validate("minimal", minimal)
	held := statusFixture()
	held.Held = []client.HeldStatus{{Name: "homelab-nas", IPv4: "100.64.0.3", Kind: "server", PinnedKey: "NAS=", OfferedKey: "NEW=", Since: held.RetrievedAt, Reason: client.HeldKeyChanged}}
	held.Peers[0].Path, held.Peers[0].PublicKey = client.PathKeyChanged, "NEW="
	validate("held", held)
	bad := statusFixture()
	bad.Peers[0].Path = "teleport"
	data, _ := json.Marshal(bad)
	v, _ := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err := sch.Validate(v); err == nil {
		t.Error("schema accepted an unknown path state")
	}
}

// fakeDaemon serves a canned status document on a Unix socket.
func fakeDaemon(t *testing.T, st client.Status) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(st)
	})
	return fakeDaemonSocket(t, mux)
}

// fakeDaemonSocket serves h on a short Unix socket path.
func fakeDaemonSocket(t *testing.T, h http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "th")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestStatusExitCodes(t *testing.T) {
	connected := statusFixture()
	cached := statusFixture()
	cached.Server.State = client.ServerCached
	cases := []struct {
		name string
		args []string
		sock string
		code int
		want string
	}{
		{"connected", []string{"client", "status"}, fakeDaemon(t, connected), 0, "connected (netmap #42"},
		{"connected json", []string{"client", "status", "--json"}, fakeDaemon(t, connected), 0, `"state": "connected"`},
		{"cached", []string{"client", "status"}, fakeDaemon(t, cached), exitNotConnected, "cached netmap"},
		{"not running", []string{"client", "status"}, filepath.Join(t.TempDir(), "missing.sock"), exitNotRunning, ""},
		{"usage", []string{"client", "status", "--bogus"}, "", exitConfigError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			root := newRootCmd(&out, &errOut)
			args := tc.args
			if tc.sock != "" {
				args = append(args, "--socket", tc.sock)
			}
			root.SetArgs(args)
			err := root.ExecuteContext(context.Background())
			code := 0
			var ee *exitError
			if errors.As(err, &ee) {
				code = ee.code
			} else if err != nil {
				code = 1
			}
			if code != tc.code {
				t.Errorf("exit %d (err %v), want %d", code, err, tc.code)
			}
			if tc.want != "" && !strings.Contains(out.String(), tc.want) {
				t.Errorf("output lacks %q:\n%s", tc.want, out.String())
			}
		})
	}
}

// TestStatusRenderHeld: a held peer shows "key changed" and the header
// names the command that clears it.
func TestStatusRenderHeld(t *testing.T) {
	st := statusFixture()
	st.Held = []client.HeldStatus{
		{Name: "build-box", IPv4: "100.64.0.9", Kind: "agent", PinnedKey: "BLD=", OfferedKey: "NEW=", Since: st.RetrievedAt},
		{Name: "hub", IPv4: "100.64.0.1", Kind: "server", PinnedKey: "HUB=", OfferedKey: "HUB2=", Since: st.RetrievedAt},
	}
	st.Peers[1].Path, st.Peers[1].PathEndpoint, st.Peers[1].LastHandshakeAt = client.PathKeyChanged, "", nil
	st.Hub.Path, st.Hub.PathEndpoint, st.Hub.LastHandshakeAt = client.PathKeyChanged, "", nil
	var out bytes.Buffer
	if err := renderStatus(&out, st); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{" · 2 keys changed: thawr client trust build-box hub\n", "build-box     100.64.0.9    agent    -       key changed", "hub           100.64.0.1    server   -       key changed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if heldLine(st.Held[:1]) != " · 1 key changed: thawr client trust build-box" {
		t.Errorf("single: %q", heldLine(st.Held[:1]))
	}
}
