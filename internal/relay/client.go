package relay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ClientOptions configure a Client. Zero values select the spec
// defaults.
type ClientOptions struct {
	ServerURL  string
	TLS        *tls.Config
	NodeSecret string
	// WireGuardPort is the local WireGuard listen port RECV payloads are
	// delivered to.
	WireGuardPort int
	// IdleTimeout closes the connection after that long without proxies
	// (5 min); ReleaseDelay keeps a released proxy open briefly (10 s)
	// so in-flight packets still arrive.
	IdleTimeout  time.Duration
	ReleaseDelay time.Duration
	MinBackoff   time.Duration
	MaxBackoff   time.Duration
	PingInterval time.Duration
	MissedPings  int
	Logger       *slog.Logger
	Now          func() time.Time
	// Dial overrides the connection (tests); the default is Dial with
	// ServerURL, TLS and NodeSecret.
	Dial func(ctx context.Context) (net.Conn, error)
}

func (o ClientOptions) withDefaults() ClientOptions {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 5 * time.Minute
	}
	if o.ReleaseDelay <= 0 {
		o.ReleaseDelay = 10 * time.Second
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = time.Second
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 60 * time.Second
	}
	if o.PingInterval <= 0 {
		o.PingInterval = 30 * time.Second
	}
	if o.MissedPings <= 0 {
		o.MissedPings = 3
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Dial == nil {
		url, cfg, secret := o.ServerURL, o.TLS, o.NodeSecret
		o.Dial = func(ctx context.Context) (net.Conn, error) { return Dial(ctx, url, cfg, secret) }
	}
	return o
}

// Client keeps one relay connection, opened lazily, and one loopback
// UDP proxy per relayed peer. WireGuard's endpoint for such a peer is
// the proxy address; datagrams it sends there become SEND frames and
// RECV frames come back out of the proxy toward the WireGuard port.
type Client struct {
	opts ClientOptions
	log  *slog.Logger

	mu        sync.Mutex
	proxies   map[Key]*proxy
	releasing map[Key]*time.Timer
	idleSince time.Time
	running   bool
	cancel    context.CancelFunc
	done      chan struct{}
	closed    bool
	connected atomic.Bool

	out chan Frame
}

type proxy struct {
	key  Key
	conn *net.UDPConn
	addr netip.AddrPort
}

// NewClient returns a client that connects on first use.
func NewClient(opts ClientOptions) *Client {
	opts = opts.withDefaults()
	return &Client{opts: opts, log: opts.Logger, proxies: map[Key]*proxy{}, releasing: map[Key]*time.Timer{}, out: make(chan Frame, 256)}
}

// ErrClientClosed is returned after Close.
var ErrClientClosed = errors.New("relay: client closed")

// Endpoint returns the loopback address WireGuard should use for peer
// key, creating the proxy and the relay connection as needed.
func (c *Client) Endpoint(ctx context.Context, key Key) (netip.AddrPort, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return netip.AddrPort{}, ErrClientClosed
	}
	if t, ok := c.releasing[key]; ok {
		t.Stop()
		delete(c.releasing, key)
	}
	if p, ok := c.proxies[key]; ok {
		return p.addr, nil
	}
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("relay: proxy socket: %w", err)
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return netip.AddrPort{}, errors.New("relay: proxy socket is not UDP")
	}
	p := &proxy{key: key, conn: uc, addr: uc.LocalAddr().(*net.UDPAddr).AddrPort()}
	c.proxies[key] = p
	go c.readProxy(p)
	if !c.running {
		c.running = true
		runCtx, cancel := context.WithCancel(context.Background())
		c.cancel, c.done = cancel, make(chan struct{})
		go c.run(runCtx)
	}
	return p.addr, nil
}

// Release closes the proxy for key after ReleaseDelay unless Endpoint
// asks for it again first.
func (c *Client) Release(key Key) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.proxies[key]; !ok || c.releasing[key] != nil {
		return
	}
	c.releasing[key] = time.AfterFunc(c.opts.ReleaseDelay, func() { c.dropProxy(key) })
}

func (c *Client) dropProxy(key Key) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.releasing, key)
	if p, ok := c.proxies[key]; ok {
		_ = p.conn.Close()
		delete(c.proxies, key)
	}
	if len(c.proxies) == 0 {
		c.idleSince = c.opts.Now()
	}
}

// Connected reports whether the relay connection is up.
func (c *Client) Connected() bool { return c.connected.Load() }

// Peers counts the relayed peers (open proxies).
func (c *Client) Peers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.proxies)
}

// Close drops every proxy and the connection.
func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	for k, t := range c.releasing {
		t.Stop()
		delete(c.releasing, k)
	}
	for k, p := range c.proxies {
		_ = p.conn.Close()
		delete(c.proxies, k)
	}
	cancel, done := c.cancel, c.done
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// readProxy turns datagrams WireGuard sends to the proxy into frames.
func (c *Client) readProxy(p *proxy) {
	buf := make([]byte, MaxPayload+1)
	for {
		n, _, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Windows reports an ICMP unreachable for an earlier send as
			// a read error; the socket itself is fine.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n > MaxPayload || !IsWireGuard(buf[:n]) {
			continue
		}
		// Frames wait in the bounded queue while the connection is still
		// being set up and leave once it is up: the first one is
		// usually the handshake that opened the relay path, and dropping
		// it cost a 5 s WireGuard retry. A full queue drops, as UDP does.
		f := Frame{Type: TypeSend, Key: p.key, Payload: append([]byte(nil), buf[:n]...)}
		select {
		case c.out <- f:
		default:
		}
	}
}

// run keeps the connection alive until the client closes or idles out.
func (c *Client) run(ctx context.Context) {
	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
		close(c.done)
	}()
	attempt := 0
	for {
		if c.idle() {
			c.log.Info("relay connection closed: no relayed peers")
			return
		}
		conn, err := c.opts.Dial(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			attempt++
			delay := backoff(attempt, c.opts.MinBackoff, c.opts.MaxBackoff)
			c.log.Warn("relay connect failed", "err", err, "retry_in", delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			continue
		}
		attempt = 0
		c.log.Info("relay connected")
		err = c.serve(ctx, conn)
		c.log.Info("relay disconnected", "reason", closeReason(err))
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff(1, c.opts.MinBackoff, c.opts.MaxBackoff)):
		}
	}
}

// idle reports whether the connection has had no proxies for IdleTimeout.
func (c *Client) idle() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.proxies) == 0 && !c.idleSince.IsZero() && c.opts.Now().Sub(c.idleSince) >= c.opts.IdleTimeout
}

// serve runs one connection: writer, pinger, idle check and the reader
// in this goroutine.
func (c *Client) serve(ctx context.Context, conn net.Conn) error {
	c.connected.Store(true)
	defer c.connected.Store(false)
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done); _ = conn.Close() }) }
	defer stop()
	var missed atomic.Int32
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				stop()
				return
			case f := <-c.out:
				if err := WriteFrame(conn, f); err != nil {
					stop()
					return
				}
			}
		}
	}()
	go func() {
		ping := time.NewTicker(c.opts.PingInterval)
		defer ping.Stop()
		idle := time.NewTicker(c.opts.IdleTimeout / 4)
		defer idle.Stop()
		for {
			select {
			case <-done:
				return
			case <-ping.C:
				if int(missed.Add(1)) > c.opts.MissedPings {
					c.log.Warn("relay server stopped answering pings")
					stop()
					return
				}
				c.enqueue(Frame{Type: TypePing})
			case <-idle.C:
				if c.idle() {
					stop()
					return
				}
			}
		}
	}()
	buf := make([]byte, HeaderLen+MaxPayload)
	for {
		f, err := ReadFrame(conn, buf)
		if err != nil {
			return err
		}
		switch f.Type {
		case TypeRecv:
			c.deliver(f)
		case TypePing:
			c.enqueue(Frame{Type: TypePong})
		case TypePong:
			missed.Store(0)
		case TypePeerGone:
			c.log.Debug("relay: peer gone", "peer", fingerprint(f.Key))
		}
	}
}

func (c *Client) enqueue(f Frame) {
	select {
	case c.out <- f:
	default:
	}
}

// deliver writes a RECV payload to the WireGuard port from the proxy of
// its source peer, so WireGuard sees the proxy as the peer's endpoint.
func (c *Client) deliver(f Frame) {
	c.mu.Lock()
	p, ok := c.proxies[f.Key]
	c.mu.Unlock()
	if !ok {
		return
	}
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.opts.WireGuardPort}
	_, _ = p.conn.WriteToUDP(f.Payload, dst)
}

// backoff is exponential from min with ±20 % jitter, capped at max.
func backoff(attempt int, minDelay, maxDelay time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := math.Min(float64(minDelay)*math.Pow(2, float64(attempt-1)), float64(maxDelay))
	var b [1]byte
	_, _ = rand.Read(b[:])
	d *= 1 + (float64(b[0])/255-0.5)*0.4
	return time.Duration(math.Max(float64(minDelay), math.Min(d, float64(maxDelay))))
}
