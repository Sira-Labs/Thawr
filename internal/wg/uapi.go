package wg

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// renderUAPI converts a Config into the wireguard-go IPC "set" format.
// Listed peers are created or updated in place; keys in remove are
// deleted. Peers are never replaced wholesale, so unchanged peers keep
// their sessions.
func renderUAPI(cfg Config, remove []Key) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	}
	// Always written: fwmark=0 clears a mark left by an exit node.
	fmt.Fprintf(&b, "fwmark=%d\n", cfg.FwMark)
	for _, k := range remove {
		b.WriteString(renderRemoveUAPI(k))
	}
	for _, p := range cfg.Peers {
		b.WriteString(renderPeerUAPI(p))
	}
	return b.String()
}

// renderPeerUAPI renders one peer section (create or update).
func renderPeerUAPI(p Peer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
	if p.Endpoint.IsValid() {
		fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint.String())
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, ip := range p.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", ip.String())
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(p.Keepalive/time.Second))
	return b.String()
}

// renderRemoveUAPI renders the removal of one peer.
func renderRemoveUAPI(k Key) string {
	return fmt.Sprintf("public_key=%s\nremove=true\n", hex.EncodeToString(k[:]))
}

// parseUAPIStats extracts per-peer statistics from the IPC "get" output.
func parseUAPIStats(out string) ([]PeerStats, error) {
	var (
		stats   []PeerStats
		current *PeerStats
		sec     int64
		nsec    int64
	)
	flush := func() {
		if current != nil {
			if sec > 0 || nsec > 0 {
				current.LastHandshake = time.Unix(sec, nsec)
			}
			stats = append(stats, *current)
		}
		current, sec, nsec = nil, 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("wg: malformed uapi line %q", line)
		}
		switch key {
		case "public_key":
			flush()
			raw, err := hex.DecodeString(val)
			if err != nil || len(raw) != 32 {
				return nil, fmt.Errorf("wg: bad public_key in uapi output")
			}
			current = &PeerStats{}
			copy(current.PublicKey[:], raw)
		case "endpoint":
			if current != nil {
				if ap, err := netip.ParseAddrPort(val); err == nil {
					current.Endpoint = ap
				}
			}
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(val, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(val, 10, 64)
		case "rx_bytes":
			if current != nil {
				current.RxBytes, _ = strconv.ParseUint(val, 10, 64)
			}
		case "tx_bytes":
			if current != nil {
				current.TxBytes, _ = strconv.ParseUint(val, 10, 64)
			}
		case "errno":
			if val != "0" {
				return nil, fmt.Errorf("wg: uapi errno %s", val)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("wg: read uapi output: %w", err)
	}
	flush()
	return stats, nil
}
