package stun

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultRatePerIP is the binding requests per second one source IP may
// send before the server drops the rest.
const DefaultRatePerIP = 20

// Counters count what Serve did with each request, for metrics; one
// value may be shared by several listeners.
type Counters struct {
	// OK requests were answered.
	OK atomic.Uint64
	// RateLimited requests exceeded the per-IP rate and were dropped.
	RateLimited atomic.Uint64
	// Malformed packets were not Thawr binding requests.
	Malformed atomic.Uint64
}

// ServerOptions configure Serve.
type ServerOptions struct {
	// RatePerIP defaults to DefaultRatePerIP.
	RatePerIP int
	Now       func() time.Time
	Logger    *slog.Logger
	// Counters, when set, is incremented for every request.
	Counters *Counters
}

func (o ServerOptions) withDefaults() ServerOptions {
	if o.RatePerIP <= 0 {
		o.RatePerIP = DefaultRatePerIP
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Counters == nil {
		o.Counters = &Counters{}
	}
	return o
}

// Serve answers binding requests on conn until ctx ends or conn is
// closed. Requests that are not Thawr binding requests, or exceed the
// per-IP rate, are dropped silently (logged at debug).
func Serve(ctx context.Context, conn net.PacketConn, opts ServerOptions) error {
	opts = opts.withDefaults()
	log := opts.Logger.With("stun", conn.LocalAddr().String())
	limit := newIPLimiter(opts.Now, opts.RatePerIP)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	buf := make([]byte, MaxPacket)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		from := ua.AddrPort()
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if !limit.allow(from.Addr()) {
			opts.Counters.RateLimited.Add(1)
			log.Debug("stun request dropped by rate limit", "from", from.Addr())
			continue
		}
		tx, err := ParseBindingRequest(buf[:n])
		if err != nil {
			opts.Counters.Malformed.Add(1)
			log.Debug("stun request ignored", "from", from, "err", err)
			continue
		}
		if _, err := conn.WriteTo(Response(tx, from), addr); err != nil {
			if ctx.Err() == nil {
				log.Debug("stun response failed", "to", from, "err", err)
			}
			continue
		}
		opts.Counters.OK.Add(1)
	}
}

// ipLimiter allows max requests per source address per one-second window.
type ipLimiter struct {
	now func() time.Time
	max int

	mu      sync.Mutex
	buckets map[netip.Addr]bucket
	seen    int
}

type bucket struct {
	start time.Time
	count int
}

func newIPLimiter(now func() time.Time, max int) *ipLimiter {
	return &ipLimiter{now: now, max: max, buckets: map[netip.Addr]bucket{}}
}

func (l *ipLimiter) allow(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[ip]
	if now.Sub(b.start) >= time.Second {
		b = bucket{start: now}
	}
	b.count++
	l.buckets[ip] = b
	l.seen++
	if l.seen >= 1024 {
		l.seen = 0
		for k, v := range l.buckets {
			if now.Sub(v.start) >= 2*time.Second {
				delete(l.buckets, k)
			}
		}
	}
	return b.count <= l.max
}
