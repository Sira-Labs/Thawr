package config

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
)

// Config is the complete server configuration. Every field has a default
// except PublicAddr. Field names and YAML keys mirror
// config/server.example.yaml.
type Config struct {
	// PublicAddr is the host or host:port peers use to reach the server.
	PublicAddr string `yaml:"public_addr"`
	// DataDir holds the SQLite database, keys, TLS files and admin socket.
	DataDir string  `yaml:"data_dir"`
	Listen  Listen  `yaml:"listen"`
	Overlay Overlay `yaml:"overlay"`
	TLS     TLS     `yaml:"tls"`
	// PolicyFile is the YAML ACL file. Absent means empty policy.
	PolicyFile string `yaml:"policy_file"`
	// AdminSocket is the Unix socket path for the local admin API.
	AdminSocket string `yaml:"admin_socket"`
	Log         Log    `yaml:"log"`
	// MinClientVersion is MAJOR.MINOR; empty means the server's own.
	MinClientVersion string  `yaml:"min_client_version"`
	Relay            Relay   `yaml:"relay"`
	DNS              DNS     `yaml:"dns"`
	Audit            Audit   `yaml:"audit"`
	Metrics          Metrics `yaml:"metrics"`
}

// Metrics configures the Prometheus endpoint (spec 014). /metrics is
// always served on the admin socket; Listen adds a plain-HTTP listener.
type Metrics struct {
	// Listen is the host:port of a plain-HTTP listener that serves only
	// /metrics, without authentication; empty (the default) opens none.
	Listen string `yaml:"listen"`
}

// Audit tunes the audit log of control-plane mutations (spec 011).
type Audit struct {
	// RetentionDays is how long entries are kept; 0 keeps them forever.
	RetentionDays int `yaml:"retention_days"`
}

// Audit retention bounds: the default, and the largest day count whose
// duration still fits time.Duration.
const (
	DefaultAuditRetentionDays = 90
	MaxAuditRetentionDays     = 106751
)

// DNS configures the hub resolver: <name>.thawr for phones and any
// peer that asks the hub address (spec 010).
type DNS struct {
	// Enabled binds the resolver on the hub address, port 53.
	Enabled bool `yaml:"enabled"`
	// Upstream lists the resolvers queries outside the zone are
	// forwarded to (IP or IP:port). Empty means the nameservers of the
	// server host's /etc/resolv.conf, read at start.
	Upstream []string `yaml:"upstream"`
}

// Relay tunes the packet relay built into the server.
type Relay struct {
	// MaxBytesPerSecond limits what one peer may send through the
	// relay; 0 means unlimited.
	MaxBytesPerSecond int `yaml:"max_bytes_per_second"`
}

// Listen holds the listener addresses.
type Listen struct {
	// HTTPS serves gRPC, REST, the admin UI and the relay.
	HTTPS string `yaml:"https"`
	// STUN lists one or two UDP addresses; two let clients detect
	// endpoint-dependent NAT.
	STUN []string `yaml:"stun"`
	// WireGuard is the UDP address of the server's own WireGuard hub.
	WireGuard string `yaml:"wireguard"`
}

// Overlay describes the private address space.
type Overlay struct {
	CIDR      string `yaml:"cidr"`
	Interface string `yaml:"interface"`
}

// TLS selects how the HTTPS certificate is obtained.
type TLS struct {
	// Mode is "self-signed" (generated into DataDir) or "file".
	Mode     string `yaml:"mode"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Log configures slog output.
type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// TLS modes.
const (
	TLSModeSelfSigned = "self-signed"
	TLSModeFile       = "file"
)

// DefaultDataDir is used when data_dir is not set.
const DefaultDataDir = "/var/lib/thawr"

// DefaultInterface is the WireGuard interface name used when none is
// configured: thawr0, except on macOS, which only accepts utun names and
// assigns the number itself.
func DefaultInterface() string {
	if runtime.GOOS == "darwin" {
		return "utun"
	}
	return "thawr0"
}

// Default returns a Config with every default applied and PublicAddr
// empty. Validate fails on it until PublicAddr is set.
func Default() *Config {
	return &Config{
		DataDir: DefaultDataDir,
		Listen: Listen{
			HTTPS:     ":443",
			STUN:      []string{":3478", ":3479"},
			WireGuard: ":51820",
		},
		Overlay: Overlay{
			CIDR:      "100.64.0.0/10",
			Interface: DefaultInterface(),
		},
		TLS:         TLS{Mode: TLSModeSelfSigned},
		DNS:         DNS{Enabled: true},
		Audit:       Audit{RetentionDays: DefaultAuditRetentionDays},
		PolicyFile:  "/etc/thawr/policy.yaml",
		AdminSocket: filepath.Join(DefaultDataDir, "admin.sock"),
		Log:         Log{Level: "info", Format: "text"},
	}
}

// PublicHost returns the host part of PublicAddr without a port.
func (c *Config) PublicHost() string {
	host, _, err := net.SplitHostPort(c.PublicAddr)
	if err != nil {
		return c.PublicAddr
	}
	return host
}

// OverlayPrefix returns the parsed overlay CIDR. It panics only if the
// config was not validated, which is a programmer error.
func (c *Config) OverlayPrefix() netip.Prefix {
	p, err := netip.ParsePrefix(c.Overlay.CIDR)
	if err != nil {
		panic(fmt.Sprintf("config: OverlayPrefix on unvalidated config: %v", err))
	}
	return p.Masked()
}

// HubAddr is the first usable address of the overlay, assigned to the
// server's own WireGuard interface, with the overlay's prefix length.
func (c *Config) HubAddr() netip.Prefix {
	p := c.OverlayPrefix()
	return netip.PrefixFrom(p.Addr().Next(), p.Bits())
}

// STUNEndpoints are the public host joined with each STUN listen port,
// as advertised to peers.
func (c *Config) STUNEndpoints() []string {
	out := make([]string, 0, len(c.Listen.STUN))
	for _, addr := range c.Listen.STUN {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		out = append(out, net.JoinHostPort(c.PublicHost(), port))
	}
	return out
}

// DNSUpstreams parses dns.upstream; entries without a port get 53. It
// panics only on an unvalidated config, a programmer error.
func (c *Config) DNSUpstreams() []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(c.DNS.Upstream))
	for _, u := range c.DNS.Upstream {
		ap, err := parseUpstream(u)
		if err != nil {
			panic("config: DNSUpstreams on unvalidated config: " + err.Error())
		}
		out = append(out, ap)
	}
	return out
}

// parseUpstream accepts an IP or an IP:port and defaults the port to 53.
func parseUpstream(s string) (netip.AddrPort, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(a, 53), nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not an IP or IP:port", s)
	}
	if ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%q has port 0", s)
	}
	return ap, nil
}

// HubEndpoint is the public host joined with the WireGuard listen port,
// as advertised to peers.
func (c *Config) HubEndpoint() string {
	_, port, err := net.SplitHostPort(c.Listen.WireGuard)
	if err != nil {
		port = "51820"
	}
	return net.JoinHostPort(c.PublicHost(), port)
}
