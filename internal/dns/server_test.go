package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// mapSource is a Source over fixed names; it records who asked.
type mapSource struct {
	names map[string]netip.Addr
	mu    sync.Mutex
	from  []netip.Addr
}

func (m *mapSource) Lookup(_ context.Context, from netip.Addr, name string) (netip.Addr, bool) {
	m.mu.Lock()
	m.from = append(m.from, from)
	m.mu.Unlock()
	a, ok := m.names[name]
	return a, ok
}

func (m *mapSource) Reverse(_ context.Context, _ netip.Addr, addr netip.Addr) (string, bool) {
	for n, a := range m.names {
		if a == addr {
			return n, true
		}
	}
	return "", false
}

func testSource() *mapSource {
	return &mapSource{names: map[string]netip.Addr{
		"hub":          netip.MustParseAddr("100.64.0.1"),
		"alice-laptop": netip.MustParseAddr("100.64.0.7"),
		"nas":          netip.MustParseAddr("100.64.0.3"),
	}}
}

var overlay = netip.MustParsePrefix("100.64.0.0/10")

func mkQuery(t *testing.T, id uint16, name string, typ dnsmessage.Type, edns bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if edns {
		if err := b.StartAdditionals(); err != nil {
			t.Fatal(err)
		}
		if err := b.OPTResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 4096}, dnsmessage.OPTResource{}); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

type reply struct {
	header    dnsmessage.Header
	answers   []dnsmessage.Resource
	authority []dnsmessage.Resource
}

func parseReply(t *testing.T, msg []byte) reply {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := p.AllAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	return reply{header: h, answers: answers, authority: authority}
}

func TestHandleZone(t *testing.T) {
	src := testSource()
	s := NewServer(Options{Source: src, Allow: overlay})
	from := netip.MustParseAddr("100.64.0.9")
	cases := []struct {
		name  string
		qname string
		qtype dnsmessage.Type
		rcode dnsmessage.RCode
		want  string // A or PTR rdata, "" for none
	}{
		{"a record", "nas.thawr.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "100.64.0.3"},
		{"case insensitive", "Alice-Laptop.THAWR.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "100.64.0.7"},
		{"hub", "hub.thawr.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "100.64.0.1"},
		{"aaaa nodata", "nas.thawr.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, ""},
		{"unknown", "printer.thawr.", dnsmessage.TypeA, dnsmessage.RCodeNameError, ""},
		{"nested label", "a.nas.thawr.", dnsmessage.TypeA, dnsmessage.RCodeNameError, ""},
		{"apex", "thawr.", dnsmessage.TypeSOA, dnsmessage.RCodeSuccess, ""},
		{"ptr", "3.0.64.100.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeSuccess, "nas.thawr."},
		{"ptr unknown", "200.0.64.100.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeNameError, ""},
		{"outside zone refused", "example.com.", dnsmessage.TypeA, dnsmessage.RCodeRefused, ""},
		{"outside overlay ptr refused", "1.1.168.192.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeRefused, ""},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id := uint16(100 + i)
			resp, err := s.Handle(context.Background(), mkQuery(t, id, c.qname, c.qtype, false), from, false)
			if err != nil {
				t.Fatal(err)
			}
			r := parseReply(t, resp)
			if r.header.ID != id || !r.header.Response {
				t.Fatalf("header: %+v", r.header)
			}
			if r.header.RCode != c.rcode {
				t.Fatalf("rcode %v, want %v", r.header.RCode, c.rcode)
			}
			if r.header.RecursionAvailable {
				t.Error("RA set without upstreams")
			}
			if c.want == "" {
				if len(r.answers) != 0 {
					t.Fatalf("unexpected answers %v", r.answers)
				}
				checkNegativeSOA(t, c.qname, c.rcode, r)
				return
			}
			if len(r.answers) != 1 {
				t.Fatalf("answers %d", len(r.answers))
			}
			rr := r.answers[0]
			if rr.Header.TTL != uint32(TTL.Seconds()) {
				t.Errorf("ttl %d", rr.Header.TTL)
			}
			switch body := rr.Body.(type) {
			case *dnsmessage.AResource:
				if got := netip.AddrFrom4(body.A).String(); got != c.want {
					t.Errorf("A %s, want %s", got, c.want)
				}
			case *dnsmessage.PTRResource:
				if got := body.PTR.String(); got != c.want {
					t.Errorf("PTR %s, want %s", got, c.want)
				}
			default:
				t.Errorf("body %T", body)
			}
		})
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	for _, f := range src.from {
		if f != from {
			t.Errorf("source asked with from=%s", f)
		}
	}
}

func TestHandleDropsForeignSource(t *testing.T) {
	s := NewServer(Options{Source: testSource(), Allow: overlay})
	resp, err := s.Handle(context.Background(), mkQuery(t, 1, "nas.thawr.", dnsmessage.TypeA, false), netip.MustParseAddr("192.168.1.5"), false)
	if err != nil || resp != nil {
		t.Fatalf("foreign source answered: %v %v", resp, err)
	}
	if resp, _ := s.Handle(context.Background(), []byte{1, 2, 3}, netip.MustParseAddr("100.64.0.2"), false); resp != nil {
		t.Fatalf("garbage answered: %v", resp)
	}
	// The local host may always ask.
	resp, err = s.Handle(context.Background(), mkQuery(t, 2, "nas.thawr.", dnsmessage.TypeA, false), netip.MustParseAddr("127.0.0.1"), false)
	if err != nil || resp == nil {
		t.Fatalf("loopback dropped: %v %v", resp, err)
	}
}

func TestHandleRejectsNonQuery(t *testing.T) {
	s := NewServer(Options{Source: testSource()})
	q := mkQuery(t, 7, "nas.thawr.", dnsmessage.TypeA, false)
	q[2] |= 0x80 // QR bit: a response, not a query
	resp, err := s.Handle(context.Background(), q, netip.MustParseAddr("100.64.0.2"), false)
	if err != nil {
		t.Fatal(err)
	}
	if r := parseReply(t, resp); r.header.RCode != dnsmessage.RCodeNotImplemented {
		t.Fatalf("rcode %v", r.header.RCode)
	}
}

// TestTruncation answers a client with a 512-byte buffer with TC when
// the reply would not fit, and in full when EDNS raises the limit.
func TestTruncation(t *testing.T) {
	s := NewServer(Options{Source: testSource()})
	from := netip.MustParseAddr("100.64.0.2")
	q := query{header: dnsmessage.Header{ID: 9}, question: dnsmessage.Question{Name: dnsmessage.MustNewName("nas.thawr."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, udpSize: maxUDP}
	var answers []dnsmessage.Resource
	for i := 0; i < 40; i++ {
		answers = append(answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: q.question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
			Body:   &dnsmessage.AResource{A: [4]byte{100, 64, 0, byte(i)}},
		})
	}
	resp, err := s.respond(q, dnsmessage.RCodeSuccess, answers, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := parseReply(t, resp); !r.header.Truncated || len(r.answers) != 0 {
		t.Fatalf("udp: truncated=%v answers=%d", r.header.Truncated, len(r.answers))
	}
	resp, err = s.respond(q, dnsmessage.RCodeSuccess, answers, true)
	if err != nil {
		t.Fatal(err)
	}
	if r := parseReply(t, resp); r.header.Truncated || len(r.answers) != 40 {
		t.Fatalf("tcp: truncated=%v answers=%d", r.header.Truncated, len(r.answers))
	}
	q.edns, q.udpSize = true, 4096
	resp, err = s.respond(q, dnsmessage.RCodeSuccess, answers, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := parseReply(t, resp); r.header.Truncated || len(r.answers) != 40 {
		t.Fatalf("edns: truncated=%v answers=%d", r.header.Truncated, len(r.answers))
	}
	// A real EDNS query is parsed into the larger limit.
	resp, err = s.Handle(context.Background(), mkQuery(t, 3, "nas.thawr.", dnsmessage.TypeA, true), from, false)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		t.Fatal(err)
	}
	_ = p.SkipAllQuestions()
	_ = p.SkipAllAnswers()
	_ = p.SkipAllAuthorities()
	add, err := p.AllAdditionals()
	if err != nil || len(add) != 1 || add[0].Header.Type != dnsmessage.TypeOPT {
		t.Fatalf("edns reply lacks OPT: %v %v", add, err)
	}
}

// fakeUpstream answers every query over a pipe with the given rcode and
// an A record, or hangs when hang is set.
type fakeUpstream struct {
	rcode dnsmessage.RCode
	hang  bool
	asked int
}

func (f *fakeUpstream) dial(ctx context.Context, _ string, _ string) (net.Conn, error) {
	f.asked++
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		buf := make([]byte, maxMessage)
		n, err := server.Read(buf)
		if err != nil {
			return
		}
		if f.hang {
			<-ctx.Done()
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil {
			return
		}
		q, err := p.Question()
		if err != nil {
			return
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true, RCode: f.rcode})
		_ = b.StartQuestions()
		_ = b.Question(q)
		if f.rcode == dnsmessage.RCodeSuccess {
			_ = b.StartAnswers()
			_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}})
		}
		msg, _ := b.Finish()
		_, _ = server.Write(msg)
	}()
	return client, nil
}

func TestForwardUDP(t *testing.T) {
	up := &fakeUpstream{rcode: dnsmessage.RCodeSuccess}
	s := NewServer(Options{Source: testSource(), Upstreams: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.53:53")}, Allow: overlay})
	s.dial = up.dial
	resp, err := s.Handle(context.Background(), mkQuery(t, 21, "example.com.", dnsmessage.TypeA, false), netip.MustParseAddr("100.64.0.21"), false)
	if err != nil {
		t.Fatal(err)
	}
	r := parseReply(t, resp)
	if r.header.ID != 21 || r.header.RCode != dnsmessage.RCodeSuccess || len(r.answers) != 1 {
		t.Fatalf("forwarded reply: %+v %d answers", r.header, len(r.answers))
	}
	if !r.header.RecursionAvailable {
		t.Error("RA not passed through")
	}
	// Zone names are never forwarded.
	up.asked = 0
	if _, err := s.Handle(context.Background(), mkQuery(t, 22, "nas.thawr.", dnsmessage.TypeA, false), netip.MustParseAddr("100.64.0.21"), false); err != nil {
		t.Fatal(err)
	}
	if up.asked != 0 {
		t.Error("zone query reached the upstream")
	}
}

func TestForwardTimeoutNextUpstream(t *testing.T) {
	first := &fakeUpstream{hang: true}
	second := &fakeUpstream{rcode: dnsmessage.RCodeNameError}
	s := NewServer(Options{Source: testSource(), Timeout: 50 * time.Millisecond,
		Upstreams: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:53"), netip.MustParseAddrPort("10.0.0.2:53")}})
	s.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "10.0.0.1:53" {
			return first.dial(ctx, network, addr)
		}
		return second.dial(ctx, network, addr)
	}
	resp, err := s.Handle(context.Background(), mkQuery(t, 5, "example.org.", dnsmessage.TypeA, false), netip.MustParseAddr("100.64.0.21"), false)
	if err != nil {
		t.Fatal(err)
	}
	if r := parseReply(t, resp); r.header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("rcode %v", r.header.RCode)
	}
	if first.asked != 1 || second.asked != 1 {
		t.Errorf("asked first=%d second=%d", first.asked, second.asked)
	}
	// Every upstream failing is SERVFAIL, not a dropped query.
	s.dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unreachable") }
	resp, err = s.Handle(context.Background(), mkQuery(t, 6, "example.org.", dnsmessage.TypeA, false), netip.MustParseAddr("100.64.0.21"), false)
	if err != nil {
		t.Fatal(err)
	}
	if r := parseReply(t, resp); r.header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode %v", r.header.RCode)
	}
}

// TestServeUDPAndTCP runs the real listeners on loopback and resolves
// through them with net.Resolver, including the TCP framing.
func TestServeUDPAndTCP(t *testing.T) {
	s := NewServer(Options{Source: testSource()})
	udp, tcp, err := Listen(context.Background(), netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, udp, tcp) }()
	t.Cleanup(func() { cancel(); <-done })

	for _, network := range []string{"udp", "tcp"} {
		addr := udp.LocalAddr().String()
		if network == "tcp" {
			addr = tcp.Addr().String()
		}
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}
		ips, err := r.LookupNetIP(ctx, "ip4", "alice-laptop.thawr")
		if err != nil {
			t.Fatalf("%s lookup: %v", network, err)
		}
		if len(ips) != 1 || ips[0].String() != "100.64.0.7" {
			t.Fatalf("%s lookup: %v", network, ips)
		}
		names, err := r.LookupAddr(ctx, "100.64.0.1")
		if err != nil || len(names) != 1 || names[0] != "hub.thawr." {
			t.Fatalf("%s reverse: %v %v", network, names, err)
		}
		if _, err := r.LookupNetIP(ctx, "ip4", "nobody.thawr"); err == nil {
			t.Fatalf("%s: unknown name resolved", network)
		} else if !strings.Contains(err.Error(), "no such host") {
			t.Fatalf("%s: unknown name error %v", network, err)
		}
	}
}

func TestReverseAddr(t *testing.T) {
	if a, ok := reverseAddr("7.0.64.100.in-addr.arpa"); !ok || a.String() != "100.64.0.7" {
		t.Fatalf("%v %v", a, ok)
	}
	for _, bad := range []string{"in-addr.arpa", "1.2.3.in-addr.arpa", "x.0.64.100.in-addr.arpa", "300.0.64.100.in-addr.arpa", "7.0.64.100.ip6.arpa"} {
		if _, ok := reverseAddr(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

// TestServeReportsListenerFailure: a listener that dies while the
// context is alive ends Serve with its error instead of a silent hang.
func TestServeReportsListenerFailure(t *testing.T) {
	s := NewServer(Options{Source: testSource()})
	udp, tcp, err := Listen(context.Background(), netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), udp, tcp) }()
	_ = tcp.Close() // simulate the listener going away underneath
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "tcp listener") {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the listener failed")
	}
}

// checkNegativeSOA: a negative answer inside the zone carries the zone's
// SOA, whose MINIMUM bounds how long it is cached (RFC 2308); answers
// outside the zone carry none.
func checkNegativeSOA(t *testing.T, qname string, rcode dnsmessage.RCode, r reply) {
	t.Helper()
	inZone := strings.HasSuffix(strings.ToLower(qname), "thawr.") && rcode != dnsmessage.RCodeRefused
	if !inZone {
		if len(r.authority) != 0 {
			t.Errorf("authority outside the zone: %v", r.authority)
		}
		return
	}
	if len(r.authority) != 1 {
		t.Fatalf("authority = %v, want the zone SOA", r.authority)
	}
	soa, ok := r.authority[0].Body.(*dnsmessage.SOAResource)
	if !ok || r.authority[0].Header.Name.String() != "thawr." || soa.MinTTL != uint32(TTL.Seconds()) || r.authority[0].Header.TTL != uint32(TTL.Seconds()) {
		t.Errorf("SOA = %+v %+v", r.authority[0].Header, r.authority[0].Body)
	}
}
