package client

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"time"

	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/control/path"
	"github.com/thedatadudech/thawr/internal/wg"
)

// Status is the daemon's state as served on the local socket and
// printed by `thawr client status --json`. The shape is documented in
// docs/status.schema.json; fields are only ever added.
type Status struct {
	Version   string       `json:"version"`
	Self      SelfStatus   `json:"self"`
	Server    ServerStatus `json:"server"`
	WireGuard WGStatus     `json:"wireguard"`
	NAT       NATStatus    `json:"nat"`
	Relay     RelayStatus  `json:"relay"`
	// Filter reports the receiver-side policy filter when the device
	// supports one.
	Filter *FilterStatus `json:"filter,omitempty"`
	// DNS reports the <name>.thawr resolver; absent with --dns off.
	DNS   *DNSStatus   `json:"dns,omitempty"`
	Hub   *PeerStatus  `json:"hub,omitempty"`
	Peers []PeerStatus `json:"peers"`
	// Held lists the netmap entries whose key differs from the pinned
	// one or that the network lock has not signed; each also appears in
	// Peers (or Hub) with path key_changed or unsigned.
	Held []HeldStatus `json:"held"`
	// Lock is the network lock as this device sees it (spec 012).
	Lock LockStatus `json:"lock"`
	// Routes are the prefixes reached through peers, ExitNode the exit
	// node in use and Advertised what this device offers to carry
	// (spec 013).
	Routes      []RouteStatus      `json:"routes"`
	ExitNode    ExitNodeStatus     `json:"exit_node"`
	Advertised  []AdvertisedStatus `json:"advertised"`
	RetrievedAt time.Time          `json:"retrieved_at"`
}

// RouteStatus is one prefix routed through the peer Via.
type RouteStatus struct {
	Prefix string `json:"prefix"`
	Via    string `json:"via"`
}

// Exit-node states.
const (
	ExitStateOff         = "off"
	ExitStateActive      = "active"
	ExitStateUnavailable = "unavailable"
)

// ExitNodeStatus is the selected exit node and whether it carries the
// default route right now.
type ExitNodeStatus struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// AdvertisedStatus is one prefix this device advertises and whether an
// admin approved it.
type AdvertisedStatus struct {
	Prefix   string `json:"prefix"`
	Approved bool   `json:"approved"`
}

// SelfStatus identifies this device.
type SelfStatus struct {
	Name   string `json:"name"`
	PeerID string `json:"peer_id"`
	IPv4   string `json:"ipv4"`
	Kind   string `json:"kind"`
}

// Server connection states.
const (
	ServerConnected    = "connected"
	ServerReconnecting = "reconnecting"
	ServerCached       = "cached"
)

// ServerStatus describes the control connection. State is connected,
// reconnecting (no netmap yet) or cached (running on the last netmap
// while the server is unreachable).
type ServerStatus struct {
	Addr  string `json:"addr"`
	State string `json:"state"`
	// Attempt counts failed connection attempts since the last
	// successful one; NextRetryAt is when the next one is due.
	Attempt          int        `json:"attempt"`
	NextRetryAt      *time.Time `json:"next_retry_at"`
	UnreachableSince *time.Time `json:"unreachable_since"`
	Generation       int64      `json:"generation"`
	LastMessageAt    *time.Time `json:"last_message_at"`
	LastError        string     `json:"last_error"`
	// Version is the server's own version from the last netmap; empty
	// until one arrived.
	Version string `json:"version"`
}

// WGStatus describes the local WireGuard interface.
type WGStatus struct {
	Backend    string `json:"backend"`
	Interface  string `json:"interface"`
	ListenPort int    `json:"listen_port"`
}

// NAT types as derived from STUN.
const (
	NATUnknown   = "unknown"
	NATNone      = "none"
	NATCone      = "cone"
	NATSymmetric = "symmetric"
)

// NATStatus is this device's own candidate addresses and the NAT
// verdict derived from them.
type NATStatus struct {
	Type      string   `json:"type"`
	Reflexive []string `json:"reflexive"`
	Local     []string `json:"local"`
}

// RelayStatus describes the relay connection.
type RelayStatus struct {
	Connected bool `json:"connected"`
	// Peers counts peers currently reached through the relay.
	Peers int `json:"peers"`
}

// FilterStatus reports the receiver-side filter counters.
type FilterStatus struct {
	Rules int    `json:"rules"`
	Drops uint64 `json:"drops"`
	// Dropped5m counts drops in the last five minutes.
	Dropped5m uint64 `json:"dropped_5m"`
	Flows     int    `json:"flows"`
}

// Candidate is one address a peer may be reached at.
type Candidate struct {
	Addr string `json:"addr"`
	Kind string `json:"kind"`
}

// Path values beyond the prober's states.
const (
	PathOffline = "offline"
	PathHub     = "hub"
	// PathKeyChanged marks a peer held out of the tunnel because its
	// key differs from the pinned one (spec 011).
	PathKeyChanged = "key_changed"
	// PathUnsigned marks a peer the network lock has not signed.
	PathUnsigned = "unsigned"
)

// PeerStatus joins netmap knowledge with device counters.
type PeerStatus struct {
	Name      string `json:"name"`
	IPv4      string `json:"ipv4"`
	Kind      string `json:"kind"`
	Owner     string `json:"owner"`
	Online    bool   `json:"online"`
	PublicKey string `json:"public_key"`
	// Path is idle, probing, direct, relay, unreachable, offline (the
	// server reports the peer offline) or hub (reached through the
	// hub); PathEndpoint is the address a direct path uses.
	Path         string `json:"path"`
	PathEndpoint string `json:"path_endpoint"`
	// Probes counts candidates tried since the peer appeared.
	Probes             int         `json:"probes"`
	EndpointCandidates []Candidate `json:"endpoint_candidates"`
	LastHandshakeAt    *time.Time  `json:"last_handshake_at"`
	RxBytes            uint64      `json:"rx_bytes"`
	TxBytes            uint64      `json:"tx_bytes"`
}

// hubStale is how old the hub handshake may be before the hub counts
// as unreachable; WireGuard keepalives run every 25 s.
const hubStale = 3 * time.Minute

// Status assembles the current status.
func (d *Daemon) Status(ctx context.Context) Status {
	now := d.opts.Now()
	d.mu.Lock()
	nm, dev, held := d.netmap, d.dev, d.held
	exitNode, advertised := d.exitNode, d.advertised
	lockSt := d.lockStatusLocked()
	srv := ServerStatus{Addr: d.state.Server, State: ServerReconnecting, Attempt: d.attempt, LastError: d.lastError,
		NextRetryAt: timePtr(d.nextRetryAt), UnreachableSince: timePtr(d.unreachableSince), LastMessageAt: timePtr(d.lastMessage)}
	if d.connected {
		srv.State = ServerConnected
	} else if nm != nil {
		srv.State = ServerCached
	}
	d.mu.Unlock()
	st := Status{
		Version:   d.opts.Version,
		Self:      SelfStatus{Name: d.state.Name, PeerID: d.state.PeerID, IPv4: d.state.IPv4},
		Server:    srv,
		WireGuard: WGStatus{Interface: d.opts.Interface, ListenPort: d.state.ListenPort},
		NAT:       NATStatus{Type: NATUnknown, Reflexive: []string{}, Local: []string{}},
		Peers:     []PeerStatus{}, Held: []HeldStatus{}, Lock: lockSt, RetrievedAt: now,
		Routes: []RouteStatus{}, ExitNode: ExitNodeStatus{Name: exitNode, State: ExitStateOff}, Advertised: []AdvertisedStatus{},
	}
	if exitNode != "" {
		st.ExitNode.State = ExitStateUnavailable
	}
	for _, a := range advertised {
		st.Advertised = append(st.Advertised, AdvertisedStatus(a))
	}
	for _, h := range held {
		st.Held = append(st.Held, h)
		ps := PeerStatus{Name: h.Name, IPv4: h.IPv4, Kind: h.Kind, Owner: h.Owner, PublicKey: h.OfferedKey, Path: PathKeyChanged, EndpointCandidates: []Candidate{}}
		if h.Reason == HeldUnsigned {
			ps.Path = PathUnsigned
		}
		if h.Name == HubName {
			ps.Online = true
			st.Hub = &ps
			continue
		}
		st.Peers = append(st.Peers, ps)
	}
	d.pmu.Lock()
	st.NAT = natStatus(d.selfAddrs, d.selfEndpoints, d.selfSymmetric)
	d.pmu.Unlock()
	st.Relay = RelayStatus{Connected: d.relay.Connected(), Peers: d.relay.Peers()}
	st.DNS = d.dnsStatus()
	stats := map[string]wg.PeerStats{}
	if dev != nil {
		st.WireGuard.Backend = dev.Backend()
		st.WireGuard.Interface = dev.Name()
		if fd, ok := dev.(wg.Filterable); ok {
			fs := fd.FilterStats()
			st.Filter = &FilterStatus{Rules: fs.Rules, Drops: fs.Drops, Flows: fs.Flows, Dropped5m: d.drops.Delta(now, fs.Drops)}
		}
		if list, err := dev.Stats(ctx); err == nil {
			for _, s := range list {
				stats[s.PublicKey.String()] = s
			}
		}
	}
	if nm == nil {
		return st
	}
	st.Self.Kind = nm.SelfKind
	st.Server.Generation = nm.Generation
	st.Server.Version = nm.ServerVersion
	if st.Server.LastMessageAt == nil && !nm.ReceivedAt.IsZero() {
		st.Server.LastMessageAt = timePtr(nm.ReceivedAt)
	}
	fill := func(ps *PeerStatus) {
		if s, ok := stats[ps.PublicKey]; ok {
			ps.LastHandshakeAt = timePtr(s.LastHandshake)
			ps.RxBytes, ps.TxBytes = s.RxBytes, s.TxBytes
		}
	}
	if nm.Hub.PublicKey != "" {
		hub := &PeerStatus{Name: "hub", Kind: "server", PublicKey: nm.Hub.PublicKey, Online: true, EndpointCandidates: []Candidate{},
			Path: string(path.Unreachable)}
		if len(nm.Hub.AllowedIPs) > 0 {
			if pfx, err := netip.ParsePrefix(nm.Hub.AllowedIPs[0]); err == nil {
				hub.IPv4 = pfx.Addr().String()
			}
		}
		fill(hub)
		if hub.LastHandshakeAt != nil && now.Sub(*hub.LastHandshakeAt) < hubStale {
			hub.Path, hub.PathEndpoint = string(path.Direct), nm.Hub.Endpoint
		}
		st.Hub = hub
	}
	for _, p := range nm.Peers {
		ps := PeerStatus{Name: p.Name, IPv4: p.IPv4, Kind: p.Kind, Owner: p.Owner, Online: p.Online, PublicKey: p.PublicKey,
			Path: string(path.Idle), EndpointCandidates: []Candidate{}}
		for _, e := range p.Endpoints {
			ps.EndpointCandidates = append(ps.EndpointCandidates, Candidate(e))
		}
		fill(&ps)
		if p.ViaHub {
			ps.Path = PathHub
			st.Peers = append(st.Peers, ps)
			continue
		}
		if state, ep, probes, ok := d.pathOf(p.ID); ok {
			ps.Path, ps.Probes = string(state), probes
			if ep.IsValid() {
				ps.PathEndpoint = ep.String()
			}
		}
		for _, a := range p.AllowedIPs {
			if pfx, err := netip.ParsePrefix(a); err == nil && (pfx.Bits() != 32 || pfx.Addr().String() != p.IPv4) {
				st.Routes = append(st.Routes, RouteStatus{Prefix: pfx.String(), Via: p.Name})
			}
		}
		if p.ExitNode && p.Name == exitNode {
			// The default route is the client's own addition (spec 013).
			st.ExitNode.State = ExitStateActive
			st.Routes = append(st.Routes, RouteStatus{Prefix: wg.ExitRoute.String(), Via: p.Name})
		}
		// The server's presence verdict wins only while no path is in
		// use: a direct path outlives a server outage.
		if !p.Online && (ps.Path == string(path.Idle) || ps.Path == string(path.Unreachable)) {
			ps.Path = PathOffline
		}
		st.Peers = append(st.Peers, ps)
	}
	return st
}

// natStatus derives the NAT verdict from our own candidates: symmetric
// when STUN saw different mappings, none when the mapped address is one
// of ours, cone when a mapping exists, unknown when STUN never answered.
func natStatus(local []netip.Addr, eps []control.Endpoint, symmetric bool) NATStatus {
	st := NATStatus{Type: NATUnknown, Reflexive: []string{}, Local: []string{}}
	for _, e := range eps {
		switch e.Kind {
		case control.EndpointReflexive:
			st.Reflexive = append(st.Reflexive, e.Addr.String())
			if st.Type != NATNone && slices.Contains(local, e.Addr.Addr()) {
				st.Type = NATNone
			} else if st.Type == NATUnknown {
				st.Type = NATCone
			}
		case control.EndpointLocal:
			st.Local = append(st.Local, e.Addr.String())
		case control.EndpointStable:
		}
	}
	if symmetric {
		st.Type = NATSymmetric
	}
	return st
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (d *Daemon) localHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, d.Status(r.Context()))
	})
	mux.HandleFunc("POST /down", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go d.Stop()
	})
	mux.HandleFunc("POST /ping/{name}", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		res, err := d.Ping(ctx, r.PathValue("name"))
		if errors.Is(err, ErrUnknownPeer) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /trust/{name}", func(w http.ResponseWriter, r *http.Request) {
		accepted, err := d.Trust(r.Context(), []string{r.PathValue("name")})
		switch {
		case errors.Is(err, ErrNotHeld):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		case err != nil:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, TrustResult{Trusted: accepted})
	})
	mux.HandleFunc("POST /exit-node/{name}", func(w http.ResponseWriter, r *http.Request) {
		res, err := d.SetExitNode(r.Context(), r.PathValue("name"))
		switch {
		case errors.Is(err, ErrNotExitNode):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		case err != nil:
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusOK, res)
		}
	})
	mux.HandleFunc("POST /rotate-key", func(w http.ResponseWriter, r *http.Request) {
		if err := d.RotateKey(r.Context()); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	lockOp := func(w http.ResponseWriter, res LockResult, err error) {
		switch {
		case errors.Is(err, ErrUnknownPeer):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		case errors.Is(err, ErrNoLockKey), errors.Is(err, ErrNotSigner), errors.Is(err, ErrLockOff):
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		case err != nil:
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusOK, res)
		}
	}
	mux.HandleFunc("POST /lock/init", func(w http.ResponseWriter, r *http.Request) {
		res, err := d.LockInit(r.Context())
		lockOp(w, res, err)
	})
	mux.HandleFunc("POST /lock/sign/{name}", func(w http.ResponseWriter, r *http.Request) {
		res, err := d.LockSign(r.Context(), []string{r.PathValue("name")})
		lockOp(w, res, err)
	})
	mux.HandleFunc("POST /lock/key", func(w http.ResponseWriter, _ *http.Request) {
		res, err := d.LockKey()
		lockOp(w, res, err)
	})
	mux.HandleFunc("POST /lock/add-signer/{name}", func(w http.ResponseWriter, r *http.Request) {
		res, err := d.LockAddSigner(r.Context(), r.PathValue("name"), r.URL.Query().Get("key"))
		lockOp(w, res, err)
	})
	mux.HandleFunc("POST /lock/disable", func(w http.ResponseWriter, r *http.Request) {
		res, err := d.LockDisable(r.Context())
		lockOp(w, res, err)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func dirOf(path string) string { return filepath.Dir(path) }

// LocalClient talks to a running daemon over its socket.
type LocalClient struct {
	http *http.Client
}

// NewLocalClient returns a client for the socket.
func NewLocalClient(socket string) *LocalClient {
	return &LocalClient{http: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}}
}

// Status fetches the daemon status.
func (c *LocalClient) Status(ctx context.Context) (Status, error) {
	var st Status
	return st, c.do(ctx, http.MethodGet, "/status", &st)
}

// Down asks the daemon to stop.
func (c *LocalClient) Down(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/down", nil)
}

// RotateKey asks the daemon to rotate its WireGuard key.
func (c *LocalClient) RotateKey(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/rotate-key", nil)
}

// TrustResult lists the entries a trust call accepted.
type TrustResult struct {
	Trusted []HeldStatus `json:"trusted"`
}

// Trust asks the daemon to accept the offered key of a held peer
// ("all" for every held one, "hub" for the hub).
func (c *LocalClient) Trust(ctx context.Context, name string) (TrustResult, error) {
	var res TrustResult
	return res, c.do(ctx, http.MethodPost, "/trust/"+url.PathEscape(name), &res)
}

// SetExitNode asks the daemon to route internet traffic through the
// named peer, or ExitNodeOff for none.
func (c *LocalClient) SetExitNode(ctx context.Context, name string) (ExitNodeStatus, error) {
	var res ExitNodeStatus
	return res, c.do(ctx, http.MethodPost, "/exit-node/"+url.PathEscape(name), &res)
}

// LockInit asks the daemon to enable the network lock with this
// device as the first signer.
func (c *LocalClient) LockInit(ctx context.Context) (LockResult, error) {
	var res LockResult
	return res, c.do(ctx, http.MethodPost, "/lock/init", &res)
}

// LockSign asks the daemon to sign a peer ("all" for every unsigned
// one, "hub" for the hub).
func (c *LocalClient) LockSign(ctx context.Context, name string) (LockResult, error) {
	var res LockResult
	return res, c.do(ctx, http.MethodPost, "/lock/sign/"+url.PathEscape(name), &res)
}

// LockKey asks the daemon to create its lock key if needed and report
// the public key.
func (c *LocalClient) LockKey(ctx context.Context) (LockResult, error) {
	var res LockResult
	return res, c.do(ctx, http.MethodPost, "/lock/key", &res)
}

// LockAddSigner asks the daemon to add a peer to the signer set; key is
// the candidate's full lock public key as read on that device.
func (c *LocalClient) LockAddSigner(ctx context.Context, name, key string) (LockResult, error) {
	var res LockResult
	return res, c.do(ctx, http.MethodPost, "/lock/add-signer/"+url.PathEscape(name)+"?key="+url.QueryEscape(key), &res)
}

// LockDisable asks the daemon to turn the network lock off.
func (c *LocalClient) LockDisable(ctx context.Context) (LockResult, error) {
	var res LockResult
	return res, c.do(ctx, http.MethodPost, "/lock/disable", &res)
}

// Ping asks the daemon to establish a path to the named peer and
// returns its state once settled.
func (c *LocalClient) Ping(ctx context.Context, name string) (PathResult, error) {
	var res PathResult
	return res, c.do(ctx, http.MethodPost, "/ping/"+url.PathEscape(name), &res)
}

func (c *LocalClient) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://thawr"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return &LocalError{Status: resp.StatusCode, Message: e.Error}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// LocalError is a non-2xx answer from the daemon.
type LocalError struct {
	Status  int
	Message string
}

func (e *LocalError) Error() string { return e.Message }
