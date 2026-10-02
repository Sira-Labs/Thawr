package config

import (
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ValidationError lists every problem found in a Config, one per field,
// so an operator can fix them all in one pass.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "config: " + strings.Join(e.Problems, "; ")
}

var versionRe = regexp.MustCompile(`^\d+\.\d+$`)

// dnsNameRe matches a fully qualified host name with at least two
// labels; an IP literal never matches because its last label is numeric.
var dnsNameRe = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// versionBelow reports whether MAJOR.MINOR v is older than minimum; an
// empty v counts as older, since it enforces nothing.
func versionBelow(v, minimum string) bool {
	vMaj, vMin, ok := majorMinor(v)
	if !ok {
		return true
	}
	mMaj, mMin, _ := majorMinor(minimum)
	return vMaj < mMaj || (vMaj == mMaj && vMin < mMin)
}

func majorMinor(v string) (int, int, bool) {
	maj, minor, ok := strings.Cut(v, ".")
	if !ok {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(minor)
	return a, b, err1 == nil && err2 == nil
}

// Validate checks every field and returns a *ValidationError listing all
// problems, or nil.
func (c *Config) Validate() error {
	var v ValidationError
	add := func(format string, args ...any) {
		v.Problems = append(v.Problems, fmt.Sprintf(format, args...))
	}

	if c.PublicAddr == "" {
		add("public_addr: required")
	} else if host := c.PublicHost(); host == "" {
		add("public_addr: %q has no host", c.PublicAddr)
	} else if _, port, err := net.SplitHostPort(c.PublicAddr); err == nil {
		if _, perr := strconv.ParseUint(port, 10, 16); perr != nil {
			add("public_addr: port %q is not a number in 0-65535", port)
		}
	}

	if c.DataDir == "" {
		add("data_dir: required")
	}

	checkListen := func(key, addr string) {
		if _, port, err := net.SplitHostPort(addr); err != nil {
			add("%s: %q is not host:port", key, addr)
		} else if _, perr := strconv.ParseUint(port, 10, 16); perr != nil {
			add("%s: port %q is not a number in 0-65535", key, port)
		}
	}
	checkListen("listen.https", c.Listen.HTTPS)
	checkListen("listen.wireguard", c.Listen.WireGuard)
	switch n := len(c.Listen.STUN); {
	case n == 0:
		add("listen.stun: at least one address required")
	case n > 2:
		add("listen.stun: at most two addresses, got %d", n)
	}
	for i, a := range c.Listen.STUN {
		checkListen(fmt.Sprintf("listen.stun[%d]", i), a)
	}
	if c.Metrics.Listen != "" {
		checkListen("metrics.listen", c.Metrics.Listen)
	}

	if p, err := netip.ParsePrefix(c.Overlay.CIDR); err != nil {
		add("overlay.cidr: %q is not a CIDR", c.Overlay.CIDR)
	} else if !p.Addr().Is4() {
		add("overlay.cidr: only IPv4 is supported in v1")
	} else if p.Bits() > 30 {
		add("overlay.cidr: prefix must be /30 or larger to hold a hub and peers")
	}
	if c.Relay.MaxBytesPerSecond < 0 {
		add("relay.max_bytes_per_second: must not be negative")
	}
	if c.Audit.RetentionDays < 0 {
		add("audit.retention_days: must not be negative (0 keeps entries forever)")
	} else if c.Audit.RetentionDays > MaxAuditRetentionDays {
		add("audit.retention_days: %d exceeds the maximum of %d", c.Audit.RetentionDays, MaxAuditRetentionDays)
	}
	if c.Overlay.Interface == "" || len(c.Overlay.Interface) > 15 || strings.ContainsAny(c.Overlay.Interface, " /") {
		add("overlay.interface: %q must be 1-15 characters without spaces or slashes", c.Overlay.Interface)
	}

	switch c.TLS.Mode {
	case TLSModeSelfSigned:
	case TLSModeFile:
		if c.TLS.CertFile == "" {
			add("tls.cert_file: required when tls.mode is file")
		}
		if c.TLS.KeyFile == "" {
			add("tls.key_file: required when tls.mode is file")
		}
	case TLSModeACME:
		if c.TLS.Email == "" {
			add("tls.email: required when tls.mode is acme")
		} else if a, err := mail.ParseAddress(c.TLS.Email); err != nil || a.Name != "" || a.Address != c.TLS.Email {
			add("tls.email: %q is not an email address", c.TLS.Email)
		}
		if d := c.ACMEDomain(); !dnsNameRe.MatchString(d) {
			add("tls.domain: tls.mode acme needs a DNS name in tls.domain or public_addr, got %q", d)
		}
		if c.TLS.ACMEDirectory != "" {
			if u, err := url.Parse(c.TLS.ACMEDirectory); err != nil || u.Scheme != "https" || u.Host == "" {
				add("tls.acme_directory: %q must be an https URL", c.TLS.ACMEDirectory)
			}
		}
	default:
		add("tls.mode: %q must be self-signed, file or acme", c.TLS.Mode)
	}

	if c.AdminSocket == "" {
		add("admin_socket: required")
	}

	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
	default:
		add("log.level: %q must be debug, info, warn or error", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		add("log.format: %q must be text or json", c.Log.Format)
	}

	if c.MinClientVersion != "" && !versionRe.MatchString(c.MinClientVersion) {
		add("min_client_version: %q must be MAJOR.MINOR", c.MinClientVersion)
	}
	for i, u := range c.DNS.Upstream {
		if _, err := parseUpstream(u); err != nil {
			add("dns.upstream[%d]: %v", i, err)
		}
	}

	if len(v.Problems) > 0 {
		return &v
	}
	return nil
}
