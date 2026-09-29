package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Zone is the only zone Thawr serves in v1.
const Zone = "thawr"

// TTL is short because netmaps change.
const TTL = 30 * time.Second

// maxUDP is the answer size a client without EDNS accepts over UDP.
const maxUDP = 512

// maxMessage bounds any DNS message we read or build.
const maxMessage = 65535

// Source answers name and address lookups for the peer at from. Names
// carry no zone suffix. Unknown names and addresses return false.
type Source interface {
	Lookup(ctx context.Context, from netip.Addr, name string) (netip.Addr, bool)
	Reverse(ctx context.Context, from netip.Addr, addr netip.Addr) (string, bool)
}

// Options configure a Server. Zero values select the defaults.
type Options struct {
	// Zone defaults to Zone.
	Zone   string
	Source Source
	// Upstreams receive queries outside the zone; empty means REFUSED.
	Upstreams []netip.AddrPort
	// Allow limits who is answered; queries from other addresses are
	// dropped. The zero prefix allows everyone.
	Allow netip.Prefix
	// Reverse is the address range answered with PTR records; it
	// defaults to Allow. The client sets the whole overlay here while
	// answering only itself.
	Reverse netip.Prefix
	// Timeout bounds each upstream attempt (2 s).
	Timeout time.Duration
	Logger  *slog.Logger
}

func (o Options) withDefaults() Options {
	if o.Zone == "" {
		o.Zone = Zone
	}
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	if !o.Reverse.IsValid() {
		o.Reverse = o.Allow
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return o
}

// Server answers DNS queries from a Source.
type Server struct {
	opts Options
	zone string // lower-case, no dots around
	log  *slog.Logger
	// dial is the upstream dialer (tests inject a fake).
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewServer builds a resolver over o.Source. It panics only on a nil
// Source, a programmer error.
func NewServer(o Options) *Server {
	o = o.withDefaults()
	if o.Source == nil {
		panic("dns: NewServer needs a Source")
	}
	d := net.Dialer{Timeout: o.Timeout}
	return &Server{opts: o, zone: strings.ToLower(strings.Trim(o.Zone, ".")), log: o.Logger, dial: d.DialContext}
}

// Listen binds UDP and TCP on addr.
func Listen(ctx context.Context, addr netip.AddrPort) (net.PacketConn, net.Listener, error) {
	var lc net.ListenConfig
	udp, err := lc.ListenPacket(ctx, "udp", addr.String())
	if err != nil {
		return nil, nil, fmt.Errorf("dns: listen udp %s: %w", addr, err)
	}
	tcp, err := lc.Listen(ctx, "tcp", addr.String())
	if err != nil {
		_ = udp.Close()
		return nil, nil, fmt.Errorf("dns: listen tcp %s: %w", addr, err)
	}
	return udp, tcp, nil
}

// Serve answers on both listeners until ctx ends, then closes them.
// Either listener may be nil. It returns nil when ctx ended and the
// listener's error when one of them stopped on its own, after closing
// the other.
func (s *Server) Serve(ctx context.Context, udp net.PacketConn, tcp net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	failed := make(chan error, 2)
	if udp != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.serveUDP(ctx, udp); err != nil {
				failed <- err
			}
		}()
	}
	if tcp != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.serveTCP(ctx, tcp); err != nil {
				failed <- err
			}
		}()
	}
	var err error
	select {
	case <-ctx.Done():
	case err = <-failed:
		cancel()
	}
	if udp != nil {
		_ = udp.Close()
	}
	if tcp != nil {
		_ = tcp.Close()
	}
	wg.Wait()
	return err
}

// serveUDP answers datagrams until ctx ends (nil) or the socket fails.
func (s *Server) serveUDP(ctx context.Context, conn net.PacketConn) error {
	buf := make([]byte, maxMessage)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("dns: udp listener: %w", err)
		}
		req := append([]byte(nil), buf[:n]...)
		go func() {
			resp, err := s.Handle(ctx, req, sourceAddr(from), false)
			if err != nil || resp == nil {
				return
			}
			if _, err := conn.WriteTo(resp, from); err != nil && ctx.Err() == nil {
				s.log.Debug("dns: udp write", "to", from.String(), "err", err)
			}
		}()
	}
}

// serveTCP accepts connections until ctx ends (nil) or the listener
// fails.
func (s *Server) serveTCP(ctx context.Context, ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("dns: tcp listener: %w", err)
		}
		go s.serveConn(ctx, c)
	}
}

// serveConn answers length-prefixed queries on one TCP connection.
func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	from := sourceAddr(c.RemoteAddr())
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		req, err := readTCP(c)
		if err != nil {
			return
		}
		resp, err := s.Handle(ctx, req, from, true)
		if err != nil || resp == nil {
			return
		}
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := writeTCP(c, resp); err != nil {
			return
		}
	}
}

func readTCP(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, errors.New("dns: empty tcp message")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeTCP(w io.Writer, msg []byte) error {
	if len(msg) > maxMessage {
		return errors.New("dns: message too long for tcp")
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg))) //nolint:gosec // bounded by the maxMessage check above
	copy(out[2:], msg)
	_, err := w.Write(out)
	return err
}

func sourceAddr(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return v.AddrPort().Addr().Unmap()
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// query is the parsed part of a request Handle acts on.
type query struct {
	header   dnsmessage.Header
	question dnsmessage.Question
	edns     bool
	udpSize  int
}

// Handle answers one wire-format query from the peer at from. A nil
// response with a nil error means the query is dropped (a source
// outside Allow, or garbage). tcp selects the transport for size limits
// and forwarding.
func (s *Server) Handle(ctx context.Context, req []byte, from netip.Addr, tcp bool) ([]byte, error) {
	if !s.allowed(from) {
		return nil, nil
	}
	q, err := parseQuery(req)
	if err != nil {
		if q.header.ID == 0 && len(req) < 12 {
			return nil, nil
		}
		return s.respond(q, dnsmessage.RCodeFormatError, nil, tcp)
	}
	if q.header.OpCode != 0 || q.header.Response {
		return s.respond(q, dnsmessage.RCodeNotImplemented, nil, tcp)
	}
	name := strings.ToLower(strings.TrimSuffix(q.question.Name.String(), "."))
	if q.question.Class != dnsmessage.ClassINET && q.question.Class != dnsmessage.ClassANY {
		return s.respond(q, dnsmessage.RCodeRefused, nil, tcp)
	}
	if name == s.zone || strings.HasSuffix(name, "."+s.zone) {
		return s.answerZone(ctx, q, from, name, tcp)
	}
	if addr, ok := reverseAddr(name); ok && (!s.opts.Reverse.IsValid() || s.opts.Reverse.Contains(addr)) {
		return s.answerReverse(ctx, q, from, addr, tcp)
	}
	if len(s.opts.Upstreams) == 0 {
		return s.respond(q, dnsmessage.RCodeRefused, nil, tcp)
	}
	resp, err := s.forward(ctx, req, tcp)
	if err != nil {
		s.log.Debug("dns: forward failed", "name", name, "err", err)
		return s.respond(q, dnsmessage.RCodeServerFailure, nil, tcp)
	}
	return resp, nil
}

// allowed accepts sources inside Allow and the local host itself (a
// query to our own overlay address from a loopback socket).
func (s *Server) allowed(from netip.Addr) bool {
	if !s.opts.Allow.IsValid() {
		return true
	}
	return from.IsValid() && (from.IsLoopback() || s.opts.Allow.Contains(from))
}

func parseQuery(req []byte) (query, error) {
	var q query
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil {
		return q, fmt.Errorf("dns: parse header: %w", err)
	}
	q.header = h
	q.udpSize = maxUDP
	question, err := p.Question()
	if err != nil {
		return q, fmt.Errorf("dns: parse question: %w", err)
	}
	q.question = question
	// Only the first question is answered; the rest is skipped so the
	// additional section (EDNS OPT) can be read.
	if err := p.SkipAllQuestions(); err != nil {
		return q, fmt.Errorf("dns: skip questions: %w", err)
	}
	if err := p.SkipAllAnswers(); err != nil {
		return q, nil
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return q, nil
	}
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if rh.Type == dnsmessage.TypeOPT {
			q.edns = true
			if int(rh.Class) > maxUDP {
				q.udpSize = min(int(rh.Class), maxMessage)
			}
		}
		if err := p.SkipAdditional(); err != nil {
			break
		}
	}
	return q, nil
}

// answerZone handles a name at or under the zone. Negative answers
// carry the zone's SOA so resolvers cache "no such name" for TTL, not
// for a platform default of minutes (RFC 2308): a peer enrolled right
// after someone looked its name up resolves within seconds.
func (s *Server) answerZone(ctx context.Context, q query, from netip.Addr, name string, tcp bool) ([]byte, error) {
	if name == s.zone {
		if q.question.Type == dnsmessage.TypeSOA || q.question.Type == dnsmessage.TypeALL {
			soa, err := s.zoneSOA()
			if err != nil {
				return s.respond(q, dnsmessage.RCodeServerFailure, nil, tcp)
			}
			return s.respond(q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{soa}, tcp)
		}
		return s.respondNegative(q, dnsmessage.RCodeSuccess, tcp)
	}
	label := strings.TrimSuffix(name, "."+s.zone)
	if strings.Contains(label, ".") {
		return s.respondNegative(q, dnsmessage.RCodeNameError, tcp)
	}
	addr, ok := s.opts.Source.Lookup(ctx, from, label)
	if !ok {
		return s.respondNegative(q, dnsmessage.RCodeNameError, tcp)
	}
	if q.question.Type != dnsmessage.TypeA && q.question.Type != dnsmessage.TypeALL {
		return s.respondNegative(q, dnsmessage.RCodeSuccess, tcp)
	}
	if !addr.Is4() {
		return s.respondNegative(q, dnsmessage.RCodeSuccess, tcp)
	}
	rr := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: q.question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: uint32(TTL.Seconds())},
		Body:   &dnsmessage.AResource{A: addr.As4()},
	}
	return s.respond(q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{rr}, tcp)
}

// answerReverse handles in-addr.arpa for an overlay address.
func (s *Server) answerReverse(ctx context.Context, q query, from, addr netip.Addr, tcp bool) ([]byte, error) {
	name, ok := s.opts.Source.Reverse(ctx, from, addr)
	if !ok {
		return s.respond(q, dnsmessage.RCodeNameError, nil, tcp)
	}
	if q.question.Type != dnsmessage.TypePTR && q.question.Type != dnsmessage.TypeALL {
		return s.respond(q, dnsmessage.RCodeSuccess, nil, tcp)
	}
	ptr, err := dnsmessage.NewName(name + "." + s.zone + ".")
	if err != nil {
		return s.respond(q, dnsmessage.RCodeServerFailure, nil, tcp)
	}
	rr := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: q.question.Name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: uint32(TTL.Seconds())},
		Body:   &dnsmessage.PTRResource{PTR: ptr},
	}
	return s.respond(q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{rr}, tcp)
}

// respond builds the reply: the question echoed, the answers, and the
// flags a stub resolver expects. Over UDP a reply larger than the
// client's buffer is sent truncated without answers.
func (s *Server) respond(q query, rcode dnsmessage.RCode, answers []dnsmessage.Resource, tcp bool) ([]byte, error) {
	return s.respondWith(q, rcode, answers, nil, tcp)
}

// respondNegative answers NXDOMAIN or an empty NOERROR in the zone with
// its SOA in the authority section.
func (s *Server) respondNegative(q query, rcode dnsmessage.RCode, tcp bool) ([]byte, error) {
	soa, err := s.zoneSOA()
	if err != nil {
		return s.respond(q, rcode, nil, tcp)
	}
	return s.respondWith(q, rcode, nil, []dnsmessage.Resource{soa}, tcp)
}

func (s *Server) respondWith(q query, rcode dnsmessage.RCode, answers, authority []dnsmessage.Resource, tcp bool) ([]byte, error) {
	msg, err := s.build(q, rcode, answers, authority, false)
	if err != nil {
		return nil, err
	}
	if !tcp && len(msg) > q.udpSize {
		return s.build(q, rcode, nil, nil, true)
	}
	return msg, nil
}

// zoneSOA is the zone's SOA record. Its TTL and MINIMUM are TTL, which
// is how long a resolver may cache a negative answer.
func (s *Server) zoneSOA() (dnsmessage.Resource, error) {
	apex, err := dnsmessage.NewName(s.zone + ".")
	if err != nil {
		return dnsmessage.Resource{}, err
	}
	ns, err := dnsmessage.NewName("hub." + s.zone + ".")
	if err != nil {
		return dnsmessage.Resource{}, err
	}
	mbox, err := dnsmessage.NewName("hostmaster." + s.zone + ".")
	if err != nil {
		return dnsmessage.Resource{}, err
	}
	ttl := uint32(TTL.Seconds())
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: apex, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: ttl},
		Body:   &dnsmessage.SOAResource{NS: ns, MBox: mbox, Serial: 1, Refresh: ttl, Retry: ttl, Expire: ttl, MinTTL: ttl},
	}, nil
}

func (s *Server) build(q query, rcode dnsmessage.RCode, answers, authority []dnsmessage.Resource, truncated bool) ([]byte, error) {
	h := dnsmessage.Header{
		ID:                 q.header.ID,
		Response:           true,
		OpCode:             q.header.OpCode,
		Authoritative:      rcode == dnsmessage.RCodeSuccess || rcode == dnsmessage.RCodeNameError,
		Truncated:          truncated,
		RecursionDesired:   q.header.RecursionDesired,
		RecursionAvailable: len(s.opts.Upstreams) > 0,
		RCode:              rcode,
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), h)
	b.EnableCompression()
	if q.question.Name.Length > 0 {
		if err := b.StartQuestions(); err != nil {
			return nil, fmt.Errorf("dns: build: %w", err)
		}
		if err := b.Question(q.question); err != nil {
			return nil, fmt.Errorf("dns: build question: %w", err)
		}
	}
	if len(answers) > 0 {
		if err := b.StartAnswers(); err != nil {
			return nil, fmt.Errorf("dns: build: %w", err)
		}
		for _, rr := range answers {
			var err error
			switch body := rr.Body.(type) {
			case *dnsmessage.AResource:
				err = b.AResource(rr.Header, *body)
			case *dnsmessage.PTRResource:
				err = b.PTRResource(rr.Header, *body)
			case *dnsmessage.SOAResource:
				err = b.SOAResource(rr.Header, *body)
			default:
				err = fmt.Errorf("unsupported record type %v", rr.Header.Type)
			}
			if err != nil {
				return nil, fmt.Errorf("dns: build answer: %w", err)
			}
		}
	}
	if len(authority) > 0 {
		if err := b.StartAuthorities(); err != nil {
			return nil, fmt.Errorf("dns: build: %w", err)
		}
		for _, rr := range authority {
			body, ok := rr.Body.(*dnsmessage.SOAResource)
			if !ok {
				return nil, fmt.Errorf("dns: build authority: unsupported record type %v", rr.Header.Type)
			}
			if err := b.SOAResource(rr.Header, *body); err != nil {
				return nil, fmt.Errorf("dns: build authority: %w", err)
			}
		}
	}
	if q.edns {
		if err := b.StartAdditionals(); err != nil {
			return nil, fmt.Errorf("dns: build: %w", err)
		}
		opt := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: dnsmessage.Class(maxMessage & 0xffff)}
		if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
			return nil, fmt.Errorf("dns: build opt: %w", err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		return nil, fmt.Errorf("dns: finish: %w", err)
	}
	return msg, nil
}

// reverseAddr parses w.z.y.x.in-addr.arpa into the IPv4 address.
func reverseAddr(name string) (netip.Addr, bool) {
	const suffix = ".in-addr.arpa"
	if !strings.HasSuffix(name, suffix) {
		return netip.Addr{}, false
	}
	parts := strings.Split(strings.TrimSuffix(name, suffix), ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return netip.Addr{}, false
		}
		b[3-i] = byte(n)
	}
	return netip.AddrFrom4(b), true
}
