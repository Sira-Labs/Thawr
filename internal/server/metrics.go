package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/sira-labs/thawr/internal/metrics"
	"github.com/sira-labs/thawr/internal/store"
)

// peerKinds are the label values of thawr_peers, always all present.
var peerKinds = []string{store.KindHuman, store.KindServer, store.KindAgent}

// collectMetrics builds one scrape (spec 014). Every value is a count or
// a gauge; no peer name, user name, key, fingerprint or address appears.
func (s *Server) collectMetrics(ctx context.Context) ([]metrics.Family, error) {
	byKind, err := s.st.Peers().CountByKind(ctx)
	if err != nil {
		return nil, err
	}
	auditRows, err := s.st.Audit().Count(ctx)
	if err != nil {
		return nil, err
	}
	peers := make([]metrics.Sample, 0, len(peerKinds))
	for _, k := range peerKinds {
		peers = append(peers, metrics.Sample{Labels: []metrics.Label{{Name: "kind", Value: k}}, Value: float64(byKind[k])})
	}
	rs := s.relay.Stats()
	one := func(v float64) []metrics.Sample { return []metrics.Sample{{Value: v}} }
	stun := func(result string, n uint64) metrics.Sample {
		return metrics.Sample{Labels: []metrics.Label{{Name: "result", Value: result}}, Value: float64(n)}
	}
	return []metrics.Family{
		{Name: "thawr_build_info", Help: "Version of the running server; the value is always 1.", Type: metrics.Gauge,
			Samples: []metrics.Sample{{Labels: []metrics.Label{{Name: "version", Value: s.deps.Version}}, Value: 1}}},
		{Name: "thawr_uptime_seconds", Help: "Seconds since the server started.", Type: metrics.Gauge,
			Samples: one(s.deps.Now().Sub(s.startedAt).Seconds())},
		{Name: "thawr_peers", Help: "Registered peers by kind.", Type: metrics.Gauge, Samples: peers},
		{Name: "thawr_peers_online", Help: "Peers online now: agents holding a sync stream and static peers with a fresh hub handshake.", Type: metrics.Gauge,
			Samples: one(float64(s.hub.OnlineCount() + s.staticOnlineCount()))},
		{Name: "thawr_netmap_generation", Help: "Netmap generation; it grows with every change peers must learn about.", Type: metrics.Gauge,
			Samples: one(float64(s.hub.Generation()))},
		{Name: "thawr_relay_sessions", Help: "Relay sessions open now.", Type: metrics.Gauge, Samples: one(float64(rs.Sessions))},
		{Name: "thawr_relay_frames_total", Help: "Frames forwarded by the relay since start.", Type: metrics.Counter, Samples: one(float64(rs.Frames))},
		{Name: "thawr_relay_bytes_total", Help: "Bytes forwarded by the relay since start.", Type: metrics.Counter, Samples: one(float64(rs.Bytes))},
		{Name: "thawr_relay_drops_total", Help: "Relay frames dropped (rate limit or unknown destination) since start.", Type: metrics.Counter, Samples: one(float64(rs.Drops))},
		{Name: "thawr_relay_violations_total", Help: "Relay frames refused for breaking the protocol since start.", Type: metrics.Counter, Samples: one(float64(rs.Violations))},
		{Name: "thawr_stun_requests_total", Help: "STUN requests by outcome since start.", Type: metrics.Counter, Samples: []metrics.Sample{
			stun("ok", s.stunCounters.OK.Load()),
			stun("ratelimited", s.stunCounters.RateLimited.Load()),
			stun("malformed", s.stunCounters.Malformed.Load()),
		}},
		{Name: "thawr_login_failures_total", Help: "Failed admin UI logins since start.", Type: metrics.Counter, Samples: one(float64(s.users.LoginFailures()))},
		{Name: "thawr_audit_rows", Help: "Rows in the audit log.", Type: metrics.Gauge, Samples: one(float64(auditRows))},
	}, nil
}

// staticOnlineCount counts static peers whose hub handshake is fresh.
func (s *Server) staticOnlineCount() int {
	now := s.deps.Now()
	s.staticMu.Lock()
	defer s.staticMu.Unlock()
	n := 0
	for _, at := range s.staticSeen {
		if now.Sub(at) < staticOnline {
			n++
		}
	}
	return n
}

// listenMetrics opens the optional plain-HTTP metrics listener; it
// returns nil, nil, nil when metrics.listen is empty.
func (s *Server) listenMetrics(ctx context.Context, h http.Handler) (*http.Server, net.Listener, error) {
	addr := s.cfg.Metrics.Listen
	if addr == "" {
		return nil, nil, nil
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("server: listen metrics %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", h)
	mux.Handle("/", http.NotFoundHandler())
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// A scrape is a bodyless GET; ReadTimeout also bounds reading
		// any body a client sends, which ReadHeaderTimeout does not.
		ReadTimeout: 10 * time.Second,
		ErrorLog:    slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	s.log.Info("metrics listener ready", "addr", ln.Addr().String())
	return srv, ln, nil
}
