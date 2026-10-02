package stun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCodecRoundTrip(t *testing.T) {
	tx := NewTxID()
	req := Request(tx)
	if !Is(req) {
		t.Fatal("request is not recognised as STUN")
	}
	gotTx, err := ParseBindingRequest(req)
	if err != nil || gotTx != tx {
		t.Fatalf("ParseBindingRequest: %v tx=%x want %x", err, gotTx, tx)
	}
	for _, addr := range []string{"203.0.113.9:40001", "[2001:db8::1]:5"} {
		want := netip.MustParseAddrPort(addr)
		resp := Response(tx, want)
		rTx, got, err := ParseResponse(resp)
		if err != nil || rTx != tx || got != want {
			t.Errorf("ParseResponse(%s): %v tx=%x got %s", addr, err, rTx, got)
		}
	}
	if _, err := ParseBindingRequest(Response(tx, netip.MustParseAddrPort("1.2.3.4:5"))); !errors.Is(err, ErrNotBindingRequest) {
		t.Errorf("response parsed as request: %v", err)
	}
	if _, err := ParseBindingRequest([]byte("hello")); !errors.Is(err, ErrNotSTUN) {
		t.Errorf("junk: %v", err)
	}
	foreign := append([]byte(nil), req...)
	copy(foreign[24:32], "tailnode")
	if _, err := ParseBindingRequest(foreign); !errors.Is(err, ErrWrongSoftware) && !errors.Is(err, ErrWrongFingerprint) {
		t.Errorf("foreign software accepted: %v", err)
	}
}

func startServer(t *testing.T, opts ServerOptions) netip.AddrPort {
	t.Helper()
	var lc net.ListenConfig
	conn, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = Serve(ctx, conn, opts) }()
	t.Cleanup(func() { cancel(); <-done })
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestSTUNServerBinding(t *testing.T) {
	srv := startServer(t, ServerOptions{})
	ctx := context.Background()
	tr, err := NewSocketTransport(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	res, err := Discover(ctx, tr, []netip.AddrPort{srv}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(LocalPort(tr)))
	if len(res.Mapped) != 1 || res.Mapped[0] != want || res.Symmetric {
		t.Fatalf("Discover: %+v want %s", res, want)
	}
}

func TestSTUNRateLimit(t *testing.T) {
	base := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	var offset atomic.Int64
	counters := &Counters{}
	srv := startServer(t, ServerOptions{RatePerIP: 5, Counters: counters, Now: func() time.Time { return base.Add(time.Duration(offset.Load())) }})
	ctx := context.Background()
	tr, err := NewSocketTransport(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	for range 8 {
		if err := tr.Send(ctx, srv, Request(NewTxID())); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	for {
		rctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		_, _, err := tr.Recv(rctx)
		cancel()
		if err != nil {
			break
		}
		got++
	}
	if got != 5 {
		t.Fatalf("responses = %d, want 5 (rate limit)", got)
	}
	if ok, limited := counters.OK.Load(), counters.RateLimited.Load(); ok != 5 || limited != 3 {
		t.Errorf("counters ok=%d ratelimited=%d, want 5 and 3", ok, limited)
	}
	// A new window admits requests again.
	offset.Store(int64(time.Second))
	if err := tr.Send(ctx, srv, Request(NewTxID())); err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, _, err := tr.Recv(rctx); err != nil {
		t.Fatalf("after window: %v", err)
	}
	// A packet that is not a Thawr binding request is counted, not
	// answered. Serve handles packets in order, so the answer to the
	// request sent after it proves it was seen.
	offset.Store(int64(2 * time.Second))
	if err := tr.Send(ctx, srv, []byte("not stun")); err != nil {
		t.Fatal(err)
	}
	if err := tr.Send(ctx, srv, Request(NewTxID())); err != nil {
		t.Fatal(err)
	}
	rctx2, cancel2 := context.WithTimeout(ctx, time.Second)
	defer cancel2()
	if _, _, err := tr.Recv(rctx2); err != nil {
		t.Fatalf("after malformed: %v", err)
	}
	if n := counters.Malformed.Load(); n != 1 {
		t.Errorf("malformed = %d, want 1", n)
	}
}

// fakeTransport answers each request with a scripted mapping per server.
type fakeTransport struct {
	mu      sync.Mutex
	answers map[netip.AddrPort]netip.AddrPort // server -> mapped; missing = silent
	queue   chan []byte
	sent    int
}

func newFakeTransport(answers map[netip.AddrPort]netip.AddrPort) *fakeTransport {
	return &fakeTransport{answers: answers, queue: make(chan []byte, 16)}
}

func (f *fakeTransport) Send(_ context.Context, dst netip.AddrPort, pkt []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent++
	tx, err := ParseBindingRequest(pkt)
	if err != nil {
		return err
	}
	if mapped, ok := f.answers[dst]; ok {
		f.queue <- Response(tx, mapped)
	}
	return nil
}

func (f *fakeTransport) Recv(ctx context.Context) ([]byte, netip.AddrPort, error) {
	select {
	case pkt := <-f.queue:
		return pkt, netip.AddrPort{}, nil
	case <-ctx.Done():
		return nil, netip.AddrPort{}, ctx.Err()
	}
}

func (f *fakeTransport) Close() error { return nil }

func TestSymmetricDetection(t *testing.T) {
	s1 := netip.MustParseAddrPort("198.51.100.1:3478")
	s2 := netip.MustParseAddrPort("198.51.100.1:3479")
	cases := []struct {
		name      string
		answers   map[netip.AddrPort]netip.AddrPort
		symmetric bool
		mapped    int
		err       error
	}{
		{"cone", map[netip.AddrPort]netip.AddrPort{s1: netip.MustParseAddrPort("203.0.113.5:4000"), s2: netip.MustParseAddrPort("203.0.113.5:4000")}, false, 2, nil},
		{"symmetric", map[netip.AddrPort]netip.AddrPort{s1: netip.MustParseAddrPort("203.0.113.5:4000"), s2: netip.MustParseAddrPort("203.0.113.5:4001")}, true, 2, nil},
		{"one server silent", map[netip.AddrPort]netip.AddrPort{s1: netip.MustParseAddrPort("203.0.113.5:4000")}, false, 1, nil},
		{"no answer", map[netip.AddrPort]netip.AddrPort{}, false, 0, ErrNoResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newFakeTransport(tc.answers)
			res, err := Discover(context.Background(), tr, []netip.AddrPort{s1, s2}, 50*time.Millisecond)
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if res.Symmetric != tc.symmetric || len(res.Mapped) != tc.mapped {
				t.Fatalf("result = %+v, want symmetric=%v mapped=%d", res, tc.symmetric, tc.mapped)
			}
			if tc.mapped < 2 && tr.sent != 2+(2-tc.mapped) {
				t.Errorf("sent = %d requests, want one retry per silent server", tr.sent)
			}
		})
	}
}

func TestDiscoverCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Discover(ctx, newFakeTransport(nil), []netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:3478")}, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
