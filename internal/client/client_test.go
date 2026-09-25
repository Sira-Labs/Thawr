package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sira-labs/thawr/internal/api"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

type fakeEnroller struct {
	calls int
	last  control.EnrollRequest
}

func (f *fakeEnroller) Enroll(_ context.Context, req control.EnrollRequest) (control.EnrollResult, error) {
	f.calls++
	f.last = req
	if req.Token != "thawr_good" {
		return control.EnrollResult{}, control.ErrInvalidToken
	}
	return control.EnrollResult{Peer: store.Peer{ID: "p1", Name: "laptop", IPv4: "100.64.0.2"}, NodeSecret: "ns", Generation: 1}, nil
}

// startServer runs gRPC+REST over TLS HTTP/2 like the real listener.
func startServer(t *testing.T, fe *fakeEnroller) (*httptest.Server, string) {
	t.Helper()
	grpcSrv, err := api.NewGRPC(api.GRPCDeps{Enroller: fe, Hub: api.HubInfo{PublicKey: "hub", Endpoint: "vpn:51820"}, Version: "srv"})
	if err != nil {
		t.Fatal(err)
	}
	rest, err := api.NewREST(api.RESTDeps{Status: statusStub{}, UI: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("x")}}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(api.Combine(grpcSrv, rest))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, Fingerprint(ts.Certificate().Raw)
}

type statusStub struct{}

func (statusStub) Status(context.Context) (api.Status, error) { return api.Status{}, nil }

func TestEnrollRoundTrip(t *testing.T) {
	fe := &fakeEnroller{}
	ts, fp := startServer(t, fe)
	dir := t.TempDir()
	st, err := Enroll(context.Background(), Options{
		Server: "https://" + ts.Listener.Addr().String(), Token: "thawr_good", Fingerprint: fp,
		Name: "wanted", StateDir: dir, Hostname: "myhost", Version: "0.1.0",
		Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if st.Name != "laptop" || st.IPv4 != "100.64.0.2" || st.NodeSecret != "ns" || st.HubPublicKey != "hub" || st.Fingerprint != fp || st.Server != ts.Listener.Addr().String() {
		t.Errorf("state: %+v", st)
	}
	if fe.last.Hostname != "myhost" || fe.last.Name != "wanted" || fe.last.ClientVersion != "0.1.0" || fe.last.OS != runtime.GOOS {
		t.Errorf("request sent: %+v", fe.last)
	}
	if _, err := wg.ParseKey(fe.last.PublicKey); err != nil {
		t.Errorf("public key sent is invalid: %v", err)
	}
	loaded, err := LoadState(dir)
	if err != nil || loaded.PeerID != "p1" || !loaded.EnrolledAt.Equal(st.EnrolledAt) {
		t.Errorf("LoadState: %+v %v", loaded, err)
	}
	key, err := LoadKey(dir)
	if err != nil || key.PublicKey().String() != fe.last.PublicKey {
		t.Errorf("stored key does not match the enrolled key: %v", err)
	}
	if _, err := Enroll(context.Background(), Options{Server: ts.URL, Token: "thawr_good", Fingerprint: fp, StateDir: dir}); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Errorf("second enroll: %v", err)
	}
	if err := Forget(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); !errors.Is(err, ErrNotEnrolled) {
		t.Errorf("after forget: %v", err)
	}
}

func TestEnrollInvalidTokenLeavesNoState(t *testing.T) {
	fe := &fakeEnroller{}
	ts, fp := startServer(t, fe)
	dir := t.TempDir()
	_, err := Enroll(context.Background(), Options{Server: ts.URL, Token: "thawr_bad", Fingerprint: fp, StateDir: dir})
	if err == nil || !contains(err.Error(), "invalid token") {
		t.Fatalf("got %v, want invalid token", err)
	}
	if _, err := os.Stat(filepath.Join(dir, KeyFile)); !os.IsNotExist(err) {
		t.Error("key written although enrollment failed")
	}
}

func TestClientUpFingerprintMismatch(t *testing.T) {
	fe := &fakeEnroller{}
	ts, _ := startServer(t, fe)
	wrong := Fingerprint([]byte("some other certificate"))
	_, err := Enroll(context.Background(), Options{Server: ts.URL, Token: "thawr_good", Fingerprint: wrong, StateDir: t.TempDir(), Timeout: 3 * time.Second})
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("got %v, want ErrFingerprintMismatch", err)
	}
	if fe.calls != 0 {
		t.Error("token was sent to a server with the wrong certificate")
	}
	if _, err := PinnedTLSConfig("sha256:short"); err == nil {
		t.Error("malformed fingerprint accepted")
	}
}

func TestEnrollFingerprintTOFU(t *testing.T) {
	fe := &fakeEnroller{}
	ts, fp := startServer(t, fe)
	var fe2 *FingerprintError
	_, err := Enroll(context.Background(), Options{Server: ts.URL, Token: "thawr_good", StateDir: t.TempDir()})
	if !errors.As(err, &fe2) || fe2.Observed != fp {
		t.Fatalf("without fingerprint: %v", err)
	}
	if fe.calls != 0 {
		t.Error("token sent before the fingerprint was accepted")
	}
	st, err := Enroll(context.Background(), Options{Server: ts.URL, Token: "thawr_good", StateDir: t.TempDir(), AcceptFingerprint: true})
	if err != nil || st.Fingerprint != fp {
		t.Errorf("accept-fingerprint: %+v %v", st, err)
	}
}

func TestClientStateFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix modes on Windows")
	}
	dir := filepath.Join(t.TempDir(), "state")
	key, _ := wg.GenerateKey()
	if err := SaveKey(dir, key); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(dir, State{Server: "s", PeerID: "p", NodeSecret: "n"}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{KeyFile, StateFile} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o, want 600", f, fi.Mode().Perm())
		}
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %o, want 700", fi.Mode().Perm())
	}
}

func TestServerAddr(t *testing.T) {
	good := map[string]string{
		"vpn.example.com":           "vpn.example.com:443",
		"vpn.example.com:8443":      "vpn.example.com:8443",
		"https://vpn.example.com":   "vpn.example.com:443",
		"https://vpn.example.com/":  "vpn.example.com:443",
		"https://10.0.0.1:8443":     "10.0.0.1:8443",
		" https://vpn.example.com ": "vpn.example.com:443",
	}
	for in, want := range good {
		if got, err := ServerAddr(in); err != nil || got != want {
			t.Errorf("ServerAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "http://vpn.example.com", "https://vpn.example.com/api", "https://"} {
		if _, err := ServerAddr(bad); err == nil {
			t.Errorf("ServerAddr(%q) accepted", bad)
		}
	}
}

func TestDefaultDirEnv(t *testing.T) {
	t.Setenv(EnvStateDir, "/tmp/x")
	if DefaultDir() != "/tmp/x" {
		t.Errorf("env override ignored: %s", DefaultDir())
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(s) > 0 && indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

var _ http.Handler = (*http.ServeMux)(nil)

func TestShortHostname(t *testing.T) {
	cases := map[string]string{
		"alice-laptop.local":    "alice-laptop",
		"Mac-1234.fritz.box":    "Mac-1234",
		"plain":                 "plain",
		" spaced ":              "spaced",
		strings.Repeat("x", 70): strings.Repeat("x", 63),
		".leading":              ".leading",
	}
	for in, want := range cases {
		if got := shortHostname(in); got != want {
			t.Errorf("shortHostname(%q) = %q, want %q", in, got, want)
		}
	}
}
