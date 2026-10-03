package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type visFunc func(src, dst Key) bool

func (f visFunc) Visible(_ context.Context, src, dst Key) (bool, error) { return f(src, dst), nil }

func newKey(t *testing.T) Key {
	t.Helper()
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

// wgPayload is a minimal payload with a WireGuard message type byte.
func wgPayload(b ...byte) []byte {
	p := append([]byte{1, 0, 0, 0}, b...)
	return p
}

// testConn is the client end of a net.Pipe served by the relay.
type testConn struct {
	t    *testing.T
	conn net.Conn
	in   chan Frame
	done chan error // Serve's result
	errs chan error // client reader's terminal error
}

// connect starts a session; when read is false the client never reads,
// which lets tests fill the server's queue.
func connect(t *testing.T, srv *Server, key Key, read bool) *testConn {
	t.Helper()
	client, server := net.Pipe()
	tc := &testConn{t: t, conn: client, in: make(chan Frame, 1024), done: make(chan error, 1), errs: make(chan error, 1)}
	go func() { tc.done <- srv.Serve(context.Background(), server, key) }()
	waitFor(t, "session registered", func() bool { return srv.Connected(key) })
	if read {
		go func() {
			buf := make([]byte, HeaderLen+MaxPayload)
			for {
				f, err := ReadFrame(client, buf)
				if err != nil {
					tc.errs <- err
					return
				}
				f.Payload = append([]byte(nil), f.Payload...)
				tc.in <- f
			}
		}()
	}
	t.Cleanup(func() { _ = client.Close() })
	return tc
}

func (tc *testConn) send(f Frame) {
	tc.t.Helper()
	if err := WriteFrame(tc.conn, f); err != nil {
		tc.t.Fatalf("send: %v", err)
	}
}

func (tc *testConn) recv(timeout time.Duration) (Frame, bool) {
	select {
	case f := <-tc.in:
		return f, true
	case <-time.After(timeout):
		return Frame{}, false
	}
}

func (tc *testConn) closed(timeout time.Duration) bool {
	select {
	case <-tc.errs:
		return true
	case <-time.After(timeout):
		return false
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRelayVisibility(t *testing.T) {
	a, b, c, d := newKey(t), newKey(t), newKey(t), newKey(t)
	vis := visFunc(func(src, dst Key) bool { return dst != c && src != c })
	srv := NewServer(vis, ServerOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ca, cb := connect(t, srv, a, true), connect(t, srv, b, true)

	ca.send(Frame{Type: TypeSend, Key: b, Payload: wgPayload(9)})
	got, ok := cb.recv(time.Second)
	if !ok || got.Type != TypeRecv || got.Key != a || !bytes.Equal(got.Payload, wgPayload(9)) {
		t.Fatalf("b received %+v ok=%v", got, ok)
	}
	// Not visible: PEER_GONE once per second, violation counted each time.
	ca.send(Frame{Type: TypeSend, Key: c, Payload: wgPayload()})
	ca.send(Frame{Type: TypeSend, Key: c, Payload: wgPayload()})
	got, ok = ca.recv(time.Second)
	if !ok || got.Type != TypePeerGone || got.Key != c {
		t.Fatalf("expected PEER_GONE for c, got %+v ok=%v", got, ok)
	}
	if _, ok := ca.recv(100 * time.Millisecond); ok {
		t.Error("second PEER_GONE inside the rate limit window")
	}
	waitFor(t, "violations counted", func() bool { return srv.Stats().Violations == 2 })
	// Visible but not connected: PEER_GONE without a violation.
	ca.send(Frame{Type: TypeSend, Key: d, Payload: wgPayload()})
	if got, ok := ca.recv(time.Second); !ok || got.Type != TypePeerGone || got.Key != d {
		t.Fatalf("expected PEER_GONE for d, got %+v ok=%v", got, ok)
	}
	st := srv.Stats()
	if st.Violations != 2 || st.Frames != 1 || st.Bytes != uint64(len(wgPayload(9))) || st.Sessions != 2 {
		t.Errorf("stats: %+v", st)
	}
	if _, ok := cb.recv(50 * time.Millisecond); ok {
		t.Error("b received a frame it should not have")
	}
}

func TestRelayViolationsClose(t *testing.T) {
	a, c := newKey(t), newKey(t)
	srv := NewServer(visFunc(func(_, _ Key) bool { return false }), ServerOptions{MaxViolationsPerMinute: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ca := connect(t, srv, a, true)
	for range 4 {
		ca.send(Frame{Type: TypeSend, Key: c, Payload: wgPayload()})
	}
	if !ca.closed(time.Second) {
		t.Fatal("session survived repeated violations")
	}
	waitFor(t, "session removed", func() bool { return srv.Stats().Sessions == 0 })
}

func TestRelayReplaceSession(t *testing.T) {
	a, b := newKey(t), newKey(t)
	srv := NewServer(visFunc(func(_, _ Key) bool { return true }), ServerOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	first := connect(t, srv, a, true)
	second := connect(t, srv, a, true)
	if !first.closed(time.Second) {
		t.Fatal("first session not closed by the replacement")
	}
	cb := connect(t, srv, b, true)
	cb.send(Frame{Type: TypeSend, Key: a, Payload: wgPayload(1)})
	if got, ok := second.recv(time.Second); !ok || got.Key != b {
		t.Fatalf("second session did not receive: %+v ok=%v", got, ok)
	}
	if st := srv.Stats(); st.Sessions != 2 {
		t.Errorf("sessions = %d, want 2", st.Sessions)
	}
}

func TestRelayQueueOverflow(t *testing.T) {
	a, b := newKey(t), newKey(t)
	srv := NewServer(visFunc(func(_, _ Key) bool { return true }), ServerOptions{QueueSize: 4, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	connect(t, srv, a, false) // never reads: the writer blocks on the first frame
	cb := connect(t, srv, b, true)
	for range 10 {
		cb.send(Frame{Type: TypeSend, Key: a, Payload: wgPayload()})
	}
	waitFor(t, "drops counted", func() bool { return srv.Stats().Drops == 5 })
	if st := srv.Stats(); st.Frames != 5 {
		t.Errorf("stats: %+v", st)
	}
}

func TestRelayRateLimit(t *testing.T) {
	a, b := newKey(t), newKey(t)
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	srv := NewServer(visFunc(func(_, _ Key) bool { return true }), ServerOptions{MaxBytesPerSecond: 100, Now: clock, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ca, cb := connect(t, srv, a, true), connect(t, srv, b, true)
	payload := wgPayload(make([]byte, 46)...) // 50 bytes
	for range 3 {
		ca.send(Frame{Type: TypeSend, Key: b, Payload: payload})
	}
	waitFor(t, "third frame dropped", func() bool { return srv.Stats().Drops == 1 })
	for range 2 {
		if _, ok := cb.recv(time.Second); !ok {
			t.Fatal("frame within budget not delivered")
		}
	}
	mu.Lock()
	now = now.Add(time.Second)
	mu.Unlock()
	ca.send(Frame{Type: TypeSend, Key: b, Payload: payload})
	if _, ok := cb.recv(time.Second); !ok {
		t.Fatal("frame after refill not delivered")
	}
}

func TestRelayPingTimeout(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(visFunc(func(_, _ Key) bool { return true }), ServerOptions{PingInterval: 20 * time.Millisecond, MissedPings: 2, Logger: quiet})
	silent := connect(t, srv, newKey(t), true)
	if !silent.closed(time.Second) {
		t.Fatal("silent client not disconnected")
	}
	// A client that answers PING stays.
	answering := connect(t, srv, newKey(t), true)
	go func() {
		for f := range answering.in {
			if f.Type == TypePing {
				_ = WriteFrame(answering.conn, Frame{Type: TypePong})
			}
		}
	}()
	if answering.closed(200 * time.Millisecond) {
		t.Fatal("answering client disconnected")
	}
	// The server answers the client's PING too.
	pinger := connect(t, srv, newKey(t), true)
	pinger.send(Frame{Type: TypePing})
	waitFor(t, "pong", func() bool {
		f, ok := pinger.recv(50 * time.Millisecond)
		return ok && f.Type == TypePong
	})
}

func TestRelayPayloadTypeCheck(t *testing.T) {
	a, b := newKey(t), newKey(t)
	srv := NewServer(visFunc(func(_, _ Key) bool { return true }), ServerOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ca, cb := connect(t, srv, a, true), connect(t, srv, b, true)
	ca.send(Frame{Type: TypeSend, Key: b, Payload: []byte{0, 0, 0, 0}})
	ca.send(Frame{Type: TypeSend, Key: b, Payload: []byte{5, 0, 0, 0}})
	ca.send(Frame{Type: TypeSend, Key: b, Payload: []byte{1}})
	waitFor(t, "non-WireGuard payloads dropped", func() bool { return srv.Stats().Drops == 3 })
	if _, ok := cb.recv(50 * time.Millisecond); ok {
		t.Error("invalid payload forwarded")
	}
}

func TestRelayNeverLogsPayload(t *testing.T) {
	a, b := newKey(t), newKey(t)
	logs := &syncBuffer{}
	srv := NewServer(visFunc(func(_, _ Key) bool { return true }), ServerOptions{Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	ca, cb := connect(t, srv, a, true), connect(t, srv, b, true)
	payload := make([]byte, 64)
	_, _ = rand.Read(payload)
	payload[0] = 4
	ca.send(Frame{Type: TypeSend, Key: b, Payload: payload})
	if _, ok := cb.recv(time.Second); !ok {
		t.Fatal("not forwarded")
	}
	ca.send(Frame{Type: TypeSend, Key: newKey(t), Payload: payload}) // PEER_GONE path
	waitFor(t, "peer gone handled", func() bool { _, ok := ca.recv(10 * time.Millisecond); return ok })
	_ = ca.conn.Close()
	// The counter drops before the close line is written, so wait for
	// the line itself rather than the count.
	waitFor(t, "session closed", func() bool {
		return srv.Stats().Sessions == 1 && strings.Contains(logs.String(), "relay session closed")
	})
	out := logs.String()
	if !strings.Contains(out, "relay session opened") || !strings.Contains(out, "relay session closed") {
		t.Fatalf("expected lifecycle logs, got:\n%s", out)
	}
	secret := payload[1:]
	for _, enc := range []string{hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret), string(secret)} {
		if strings.Contains(out, enc) {
			t.Fatalf("payload bytes appeared in logs:\n%s", out)
		}
	}
	for _, k := range []Key{a, b} {
		if strings.Contains(out, hex.EncodeToString(k[:])) || strings.Contains(out, base64.StdEncoding.EncodeToString(k[:])) {
			t.Fatal("full public key logged; only fingerprints are allowed")
		}
	}
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestRelayPruneAndClose(t *testing.T) {
	a, b := newKey(t), newKey(t)
	srv := NewServer(visFunc(func(_, _ Key) bool { return true }), ServerOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ca, cb := connect(t, srv, a, true), connect(t, srv, b, true)
	srv.Prune(func(k Key) bool { return k == b })
	if !ca.closed(time.Second) || cb.closed(50*time.Millisecond) {
		t.Fatal("prune closed the wrong session")
	}
	if !srv.Connected(b) || srv.Connected(a) {
		t.Error("Connected after prune")
	}
	srv.Close()
	if !cb.closed(time.Second) {
		t.Fatal("Close left a session open")
	}
	client, server := net.Pipe()
	defer client.Close()
	if err := srv.Serve(context.Background(), server, a); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Serve after Close: %v", err)
	}
}

func TestRelayAbsentPeer(t *testing.T) {
	a, c, d := newKey(t), newKey(t), newKey(t)
	type pair struct{ src, dst Key }
	absent := make(chan pair, 8)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	vis := visFunc(func(src, dst Key) bool { return dst != c })
	srv := NewServer(vis, ServerOptions{Now: clock, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Absent: func(src, dst Key) { absent <- pair{src, dst} }})
	ca := connect(t, srv, a, true)

	// d may be reached but has no session: the server asks for it once
	// per PEER_GONE window, however often a sends.
	for range 3 {
		ca.send(Frame{Type: TypeSend, Key: d, Payload: wgPayload()})
	}
	select {
	case p := <-absent:
		if p.src != a || p.dst != d {
			t.Errorf("absent %+v, want a -> d", p)
		}
	case <-time.After(time.Second):
		t.Fatal("no absent report for a visible peer without a session")
	}
	select {
	case p := <-absent:
		t.Errorf("second report inside the PEER_GONE window: %+v", p)
	case <-time.After(50 * time.Millisecond):
	}
	mu.Lock()
	now = now.Add(peerGoneInterval)
	mu.Unlock()
	ca.send(Frame{Type: TypeSend, Key: d, Payload: wgPayload()})
	select {
	case <-absent:
	case <-time.After(time.Second):
		t.Fatal("no report after the window")
	}

	// A peer a may not reach is never asked to join.
	ca.send(Frame{Type: TypeSend, Key: c, Payload: wgPayload()})
	if got, ok := ca.recv(time.Second); !ok || got.Type != TypePeerGone {
		t.Fatalf("expected PEER_GONE for c, got %+v ok=%v", got, ok)
	}
	select {
	case p := <-absent:
		t.Errorf("invisible peer reported absent: %+v", p)
	case <-time.After(50 * time.Millisecond):
	}
}
