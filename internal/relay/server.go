package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Visibility decides whether two peers, by public key, may exchange
// packets. The server consults it for every SEND.
type Visibility interface {
	Visible(ctx context.Context, src, dst Key) (bool, error)
}

// ServerOptions tune the relay; zero values select the spec defaults.
type ServerOptions struct {
	// MaxBytesPerSecond limits SEND payload bytes per session; 0 is
	// unlimited.
	MaxBytesPerSecond int
	// QueueSize is the per-session outbound queue (256 frames).
	QueueSize int
	// PingInterval and MissedPings define the keepalive (30 s, 3).
	PingInterval time.Duration
	MissedPings  int
	// MaxViolationsPerMinute closes a session that keeps addressing
	// peers it may not see (10).
	MaxViolationsPerMinute int
	// Absent is told, at most once per second per pair, that src sent
	// to dst, a peer it may reach, while dst has no session; the server
	// asks dst to join the relay (spec 005). Nil does nothing.
	Absent func(src, dst Key)
	Now    func() time.Time
	Logger *slog.Logger
}

func (o ServerOptions) withDefaults() ServerOptions {
	if o.QueueSize <= 0 {
		o.QueueSize = 256
	}
	if o.PingInterval <= 0 {
		o.PingInterval = 30 * time.Second
	}
	if o.MissedPings <= 0 {
		o.MissedPings = 3
	}
	if o.MaxViolationsPerMinute <= 0 {
		o.MaxViolationsPerMinute = 10
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

// Stats are the relay counters exposed in the status endpoint.
type Stats struct {
	Sessions   int    `json:"sessions"`
	Frames     uint64 `json:"frames"`
	Bytes      uint64 `json:"bytes"`
	Drops      uint64 `json:"drops"`
	Violations uint64 `json:"violations"`
}

// Server forwards frames between authenticated sessions.
type Server struct {
	vis  Visibility
	opts ServerOptions
	log  *slog.Logger

	mu       sync.Mutex
	sessions map[Key]*session
	closed   bool

	frames, bytes, drops, violations atomic.Uint64
}

// NewServer returns an empty relay.
func NewServer(vis Visibility, opts ServerOptions) *Server {
	opts = opts.withDefaults()
	return &Server{vis: vis, opts: opts, log: opts.Logger, sessions: map[Key]*session{}}
}

// ErrServerClosed is returned by Serve after Close.
var ErrServerClosed = errors.New("relay: server closed")

// peerGoneInterval rate-limits PEER_GONE per (source, destination).
const peerGoneInterval = time.Second

type session struct {
	srv  *Server
	key  Key
	conn net.Conn
	out  chan Frame
	done chan struct{}
	once sync.Once

	missed atomic.Int32

	mu         sync.Mutex
	gone       map[Key]time.Time
	violations []time.Time
	tokens     float64
	refilled   time.Time
}

// Serve runs one session on conn for the peer with public key key until
// the connection closes, ctx ends or the session is replaced by a newer
// connection for the same key. It returns nil on a clean close.
func (s *Server) Serve(ctx context.Context, conn net.Conn, key Key) error {
	sess := &session{srv: s, key: key, conn: conn, out: make(chan Frame, s.opts.QueueSize), done: make(chan struct{}),
		gone: map[Key]time.Time{}, tokens: float64(s.opts.MaxBytesPerSecond), refilled: s.opts.Now()}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return ErrServerClosed
	}
	if old, ok := s.sessions[key]; ok {
		old.close()
		s.log.Info("relay session replaced", "peer", fingerprint(key))
	}
	s.sessions[key] = sess
	count := len(s.sessions)
	s.mu.Unlock()
	s.log.Info("relay session opened", "peer", fingerprint(key), "sessions", count)

	stop := context.AfterFunc(ctx, sess.close)
	defer stop()
	go sess.writer()
	go sess.pinger()
	err := sess.reader()
	sess.close()
	s.mu.Lock()
	if s.sessions[key] == sess {
		delete(s.sessions, key)
	}
	count = len(s.sessions)
	s.mu.Unlock()
	s.log.Info("relay session closed", "peer", fingerprint(key), "sessions", count, "reason", closeReason(err))
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func closeReason(err error) string {
	switch {
	case err == nil, errors.Is(err, io.EOF):
		return "peer closed"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	default:
		return err.Error()
	}
}

// reader handles inbound frames until the connection fails.
func (sess *session) reader() error {
	buf := make([]byte, HeaderLen+MaxPayload)
	for {
		f, err := ReadFrame(sess.conn, buf)
		if err != nil {
			return err
		}
		switch f.Type {
		case TypeSend:
			if err := sess.forward(f); err != nil {
				return err
			}
		case TypePing:
			sess.enqueue(Frame{Type: TypePong})
		case TypePong:
			sess.missed.Store(0)
		default:
			// Unknown types are ignored so the protocol can grow.
		}
	}
}

// forward delivers a SEND frame to its destination session.
func (sess *session) forward(f Frame) error {
	srv := sess.srv
	if !IsWireGuard(f.Payload) {
		srv.drops.Add(1)
		return nil
	}
	if !sess.allowBytes(len(f.Payload)) {
		srv.drops.Add(1)
		return nil
	}
	ok, err := srv.vis.Visible(context.Background(), sess.key, f.Key)
	if err != nil {
		srv.log.Warn("relay visibility lookup", "err", err)
		srv.drops.Add(1)
		return nil
	}
	if !ok {
		srv.violations.Add(1)
		sess.peerGone(f.Key)
		if sess.violation() {
			return errors.New("relay: too many visibility violations")
		}
		return nil
	}
	srv.mu.Lock()
	dst := srv.sessions[f.Key]
	srv.mu.Unlock()
	if dst == nil {
		if sess.peerGone(f.Key) && srv.opts.Absent != nil {
			srv.opts.Absent(sess.key, f.Key)
		}
		return nil
	}
	payload := append([]byte(nil), f.Payload...)
	if dst.enqueue(Frame{Type: TypeRecv, Key: sess.key, Payload: payload}) {
		srv.frames.Add(1)
		srv.bytes.Add(uint64(len(payload)))
	}
	return nil
}

// allowBytes applies the per-session token bucket (1 s burst).
func (sess *session) allowBytes(n int) bool {
	rate := sess.srv.opts.MaxBytesPerSecond
	if rate <= 0 {
		return true
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	now := sess.srv.opts.Now()
	sess.tokens += now.Sub(sess.refilled).Seconds() * float64(rate)
	sess.refilled = now
	if sess.tokens > float64(rate) {
		sess.tokens = float64(rate)
	}
	if float64(n) > sess.tokens {
		return false
	}
	sess.tokens -= float64(n)
	return true
}

// peerGone tells the client, at most once per second per destination,
// and reports whether it did.
func (sess *session) peerGone(dst Key) bool {
	now := sess.srv.opts.Now()
	sess.mu.Lock()
	last, seen := sess.gone[dst]
	if seen && now.Sub(last) < peerGoneInterval {
		sess.mu.Unlock()
		return false
	}
	sess.gone[dst] = now
	sess.mu.Unlock()
	sess.enqueue(Frame{Type: TypePeerGone, Key: dst})
	return true
}

// violation records one and reports whether the session must close.
func (sess *session) violation() bool {
	now := sess.srv.opts.Now()
	sess.mu.Lock()
	defer sess.mu.Unlock()
	kept := sess.violations[:0]
	for _, t := range sess.violations {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	sess.violations = append(kept, now)
	return len(sess.violations) > sess.srv.opts.MaxViolationsPerMinute
}

// enqueue offers f to the writer; a full queue drops it (UDP semantics).
func (sess *session) enqueue(f Frame) bool {
	select {
	case <-sess.done:
		return false
	default:
	}
	select {
	case sess.out <- f:
		return true
	default:
		sess.srv.drops.Add(1)
		return false
	}
}

func (sess *session) writer() {
	for {
		select {
		case <-sess.done:
			return
		case f := <-sess.out:
			if err := WriteFrame(sess.conn, f); err != nil {
				sess.close()
				return
			}
		}
	}
}

func (sess *session) pinger() {
	t := time.NewTicker(sess.srv.opts.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-sess.done:
			return
		case <-t.C:
			if int(sess.missed.Add(1)) > sess.srv.opts.MissedPings {
				sess.srv.log.Info("relay session timed out", "peer", fingerprint(sess.key))
				sess.close()
				return
			}
			sess.enqueue(Frame{Type: TypePing})
		}
	}
}

func (sess *session) close() {
	sess.once.Do(func() {
		close(sess.done)
		_ = sess.conn.Close()
	})
}

// Stats returns the counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	n := len(s.sessions)
	s.mu.Unlock()
	return Stats{Sessions: n, Frames: s.frames.Load(), Bytes: s.bytes.Load(), Drops: s.drops.Load(), Violations: s.violations.Load()}
}

// Connected reports whether key has a session.
func (s *Server) Connected(key Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[key]
	return ok
}

// Prune closes every session whose key keep rejects (a deleted peer).
func (s *Server) Prune(keep func(Key) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sess := range s.sessions {
		if !keep(k) {
			sess.close()
			s.log.Info("relay session pruned", "peer", fingerprint(k))
		}
	}
}

// Close ends every session; further Serve calls fail.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, sess := range s.sessions {
		sess.close()
	}
}

// fingerprint is the only form in which keys appear in logs.
func fingerprint(k Key) string {
	sum := sha256.Sum256(k[:])
	return hex.EncodeToString(sum[:4])
}

// String implements fmt.Stringer for Stats in logs.
func (st Stats) String() string {
	return fmt.Sprintf("sessions=%d frames=%d bytes=%d drops=%d violations=%d", st.Sessions, st.Frames, st.Bytes, st.Drops, st.Violations)
}
