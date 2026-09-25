package api

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/makiuchi-d/gozxing"
	gzqr "github.com/makiuchi-d/gozxing/qrcode"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/wg"
)

func TestMobileConfigRender(t *testing.T) {
	key, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	hub := HubInfo{PublicKey: "HUBPUBKEY=", Endpoint: "vpn.example.com:51820", Overlay: netip.MustParsePrefix("100.64.0.0/10")}
	got := renderWireGuardConf(key, "100.64.0.21", hub)
	want := "[Interface]\nPrivateKey = " + key.String() + "\nAddress = 100.64.0.21/32\n\n" +
		"[Peer]\nPublicKey = HUBPUBKEY=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 100.64.0.0/10\nPersistentKeepalive = 25\n"
	if got != want {
		t.Errorf("config:\n%s\nwant:\n%s", got, want)
	}
	hub.DNS = netip.MustParseAddr("100.64.0.1")
	got = renderWireGuardConf(key, "100.64.0.21", hub)
	if !strings.Contains(got, "\nAddress = 100.64.0.21/32\nDNS = 100.64.0.1, thawr\n\n[Peer]") {
		t.Errorf("config with dns:\n%s", got)
	}
}

func TestMobileEndpoint(t *testing.T) {
	var logs bytes.Buffer
	env := newRESTEnv(t, func(d *RESTDeps, e *restEnv) {
		logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		d.Logger = logger
		e.registry = control.NewRegistry(e.st, logger).WithOverlay(netip.MustParsePrefix("100.64.0.0/10"))
		d.Peers = e.registry
	})
	env.registry.WithTagAllowed(func(user, tag string) bool { return user == "alice" && tag == "tag:phones" })

	rec := env.do(env.local, session{}, http.MethodPost, "/api/v1/peers/mobile", map[string]any{"owner": "alice", "name": "alice-phone", "tags": []string{"tag:prod"}}, false)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var mv mobileView
	decode(t, rec, &mv)
	if mv.Peer.Mode != "static" || mv.Peer.Owner != "alice" || mv.Peer.Name != "alice-phone" || mv.Peer.IPv4 != "100.64.0.2" || mv.Warning != MobileWarning {
		t.Errorf("view: %+v", mv.Peer)
	}
	// The private key is in the config exactly once and nowhere else.
	priv := strings.TrimSpace(strings.SplitN(strings.SplitN(mv.Config, "PrivateKey = ", 2)[1], "\n", 2)[0])
	if len(priv) != 44 || strings.Count(rec.Body.String(), priv) != 1 {
		t.Errorf("private key appears %d times in the body", strings.Count(rec.Body.String(), priv))
	}
	if !strings.Contains(mv.Config, "PublicKey = HUBPUBKEY=") || !strings.Contains(mv.Config, "Address = 100.64.0.2/32") {
		t.Errorf("config: %s", mv.Config)
	}
	if !strings.HasPrefix(mv.QRSVG, "<svg") || !strings.Contains(mv.QRSVG, "<path") {
		t.Errorf("qr svg: %.80s", mv.QRSVG)
	}
	// TestMobileKeyNotLogged: the log has the event and not the key.
	if strings.Contains(logs.String(), priv) || !strings.Contains(logs.String(), "static peer created") {
		t.Errorf("log leaks the key or lacks the event:\n%s", logs.String())
	}
	if p, err := env.registry.Get(context.Background(), control.LocalAdmin, "alice-phone"); err != nil || strings.Contains(p.PublicKey, priv) || p.NodeSecretHash != "" {
		t.Errorf("stored peer: %+v %v", p, err)
	}

	// Members: only for themselves, only with granted tags.
	_, member := env.login("alice", "alicepassword")
	if rec := env.do(env.handler, member, http.MethodPost, "/api/v1/peers/mobile", map[string]any{"owner": "markus", "name": "p1"}, true); rec.Code != http.StatusForbidden {
		t.Errorf("member for another owner: %d", rec.Code)
	}
	if rec := env.do(env.handler, member, http.MethodPost, "/api/v1/peers/mobile", map[string]any{"owner": "alice", "name": "p2", "tags": []string{"tag:prod"}}, true); rec.Code != http.StatusForbidden {
		t.Errorf("member with ungranted tag: %d", rec.Code)
	}
	if rec := env.do(env.handler, member, http.MethodPost, "/api/v1/peers/mobile", map[string]any{"owner": "alice", "name": "p3", "tags": []string{"tag:phones"}}, true); rec.Code != http.StatusCreated {
		t.Errorf("member for self: %d %s", rec.Code, rec.Body.String())
	}
	if rec := env.do(env.local, session{}, http.MethodPost, "/api/v1/peers/mobile", map[string]any{"owner": "ghost", "name": "p4"}, false); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown owner: %d", rec.Code)
	}
	if rec := env.do(env.local, session{}, http.MethodPost, "/api/v1/peers/mobile", map[string]any{"owner": "alice", "name": "alice-phone"}, false); rec.Code != http.StatusConflict {
		t.Errorf("duplicate name: %d", rec.Code)
	}
	if rec := env.do(env.handler, session{}, http.MethodPost, "/api/v1/peers/mobile", map[string]any{"owner": "alice", "name": "p5"}, false); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rec.Code)
	}
}

// TestQRRoundTrip decodes the QR the API and CLI render back to the
// exact config text. The key is a fixed synthetic pattern, not a
// secret: the decoder used here (a ZXing port) misreads about one in a
// hundred version-12 symbols, which a random key turned into a flaky
// test; the symbol below decodes and stays the same on every run.
func TestQRRoundTrip(t *testing.T) {
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i*7 + 3)
	}
	key := wg.Key(raw)
	conf := renderWireGuardConf(key, "100.64.0.21", HubInfo{PublicKey: key.PublicKey().String(), Endpoint: "vpn.example.com:51820",
		Overlay: netip.MustParsePrefix("100.64.0.0/10"), DNS: netip.MustParseAddr("100.64.0.1")})
	q, err := qrcode.New(conf, qrcode.Medium)
	if err != nil {
		t.Fatal(err)
	}
	src := gozxing.NewLuminanceSourceFromImage(q.Image(512))
	bmp, err := gozxing.NewBinaryBitmap(gozxing.NewHybridBinarizer(src))
	if err != nil {
		t.Fatal(err)
	}
	res, err := gzqr.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.GetText() != conf {
		t.Errorf("decoded:\n%s\nwant:\n%s", res.GetText(), conf)
	}
	// The terminal rendering fits 80 columns by 40 rows.
	small := q.ToSmallString(false)
	lines := strings.Split(strings.TrimRight(small, "\n"), "\n")
	if len(lines) > 40 || len([]rune(lines[0])) > 80 {
		t.Errorf("terminal QR is %d rows x %d cols", len(lines), len([]rune(lines[0])))
	}
	if svg, err := qrSVG(conf); err != nil || !strings.Contains(svg, "viewBox") {
		t.Errorf("svg: %v", err)
	}
}
