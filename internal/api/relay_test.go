package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sira-labs/thawr/internal/relay"
	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

type fakeNodeAuth map[string]store.Peer

func (f fakeNodeAuth) PeerByNodeSecret(_ context.Context, secret string) (store.Peer, error) {
	p, ok := f[secret]
	if !ok {
		return store.Peer{}, errors.New("unknown secret")
	}
	return p, nil
}

type allVisible struct{}

func (allVisible) Visible(context.Context, relay.Key, relay.Key) (bool, error) { return true, nil }

// relayEnv is a TLS test server with the relay route and two peers.
type relayEnv struct {
	ts     *httptest.Server
	srv    *relay.Server
	keys   map[string]wg.Key // secret -> public key
	tlsCfg *tls.Config
}

func newRelayEnv(t *testing.T) *relayEnv {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	auth := fakeNodeAuth{}
	keys := map[string]wg.Key{}
	for _, secret := range []string{"secret-a", "secret-b"} {
		k, err := wg.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[secret] = k.PublicKey()
		auth[secret] = store.Peer{ID: secret, Name: secret, PublicKey: k.PublicKey().String()}
	}
	srv := relay.NewServer(allVisible{}, relay.ServerOptions{Logger: quiet})
	ui := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("Thawr")}}
	h, err := NewREST(RESTDeps{Status: fakeStatus{}, UI: ui, Logger: quiet, NodeAuth: auth, Relay: srv})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(h)
	t.Cleanup(func() { srv.Close(); ts.Close() })
	tlsCfg := ts.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return &relayEnv{ts: ts, srv: srv, keys: keys, tlsCfg: tlsCfg}
}

// rawUpgrade sends an arbitrary request over TLS and returns the status.
func (e *relayEnv) rawUpgrade(t *testing.T, method string, headers map[string]string) int {
	t.Helper()
	dialer := tls.Dialer{Config: e.tlsCfg}
	conn, err := dialer.DialContext(context.Background(), "tcp", strings.TrimPrefix(e.ts.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req, _ := http.NewRequestWithContext(context.Background(), method, e.ts.URL+"/relay", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestRelayAuth(t *testing.T) {
	env := newRelayEnv(t)
	upgrade := map[string]string{"Connection": "Upgrade", "Upgrade": relay.Protocol}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range upgrade {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	if got := env.rawUpgrade(t, http.MethodGet, upgrade); got != http.StatusUnauthorized {
		t.Errorf("no secret: %d", got)
	}
	if got := env.rawUpgrade(t, http.MethodGet, nil); got != http.StatusUnauthorized {
		t.Errorf("no secret and no upgrade headers: %d", got)
	}
	if got := env.rawUpgrade(t, http.MethodGet, with(map[string]string{"Authorization": "Bearer nope"})); got != http.StatusUnauthorized {
		t.Errorf("wrong secret: %d", got)
	}
	if got := env.rawUpgrade(t, http.MethodGet, map[string]string{"Authorization": "Bearer secret-a"}); got != http.StatusUpgradeRequired {
		t.Errorf("missing upgrade headers: %d", got)
	}
	if got := env.rawUpgrade(t, http.MethodPost, with(map[string]string{"Authorization": "Bearer secret-a"})); got != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", got)
	}
	if got := env.rawUpgrade(t, http.MethodGet, with(map[string]string{"Authorization": "Bearer secret-a"})); got != http.StatusSwitchingProtocols {
		t.Errorf("valid upgrade: %d", got)
	}
	if _, err := relay.Dial(context.Background(), env.ts.URL, env.tlsCfg, "nope"); !errors.Is(err, relay.ErrUnauthorized) {
		t.Errorf("Dial with wrong secret: %v", err)
	}
	// Without a relay server the route answers 501.
	h, _ := NewREST(RESTDeps{Status: fakeStatus{}, UI: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("x")}}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/relay", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("without relay: %d", rec.Code)
	}
}

func TestRelayUpgradeRoundTrip(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	a, err := relay.Dial(ctx, env.ts.URL, env.tlsCfg, "secret-a")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := relay.Dial(ctx, env.ts.URL, env.tlsCfg, "secret-b")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	deadline := time.Now().Add(3 * time.Second)
	for env.srv.Stats().Sessions != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("sessions: %+v", env.srv.Stats())
		}
		time.Sleep(10 * time.Millisecond)
	}
	payload := []byte{1, 0, 0, 0, 42}
	if err := relay.WriteFrame(a, relay.Frame{Type: relay.TypeSend, Key: relay.Key(env.keys["secret-b"]), Payload: payload}); err != nil {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := relay.ReadFrame(b, make([]byte, relay.HeaderLen+relay.MaxPayload))
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != relay.TypeRecv || got.Key != relay.Key(env.keys["secret-a"]) || string(got.Payload) != string(payload) {
		t.Fatalf("b received %+v", got)
	}
}
