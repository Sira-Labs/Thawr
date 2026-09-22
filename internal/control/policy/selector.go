package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// SelectorKind classifies a src or dst host selector.
type SelectorKind int

// Selector kinds.
const (
	SelAny      SelectorKind = iota + 1 // "*"
	SelUser                             // "user:name" or bare "name"
	SelGroup                            // "group:name"
	SelTag                              // "tag:name"
	SelPeer                             // "peer:name"
	SelSelf                             // "self" (dst only): same owner as the source
	SelCIDR                             // IPv4 address or prefix: peers inside the overlay, a subnet route outside it
	SelInternet                         // "internet" (dst only): any approved exit node (spec 013)
)

// Selector is one parsed src selector or dst host.
type Selector struct {
	Kind   SelectorKind
	Name   string
	Prefix netip.Prefix
}

// String renders the selector in file syntax.
func (s Selector) String() string {
	switch s.Kind {
	case SelAny:
		return "*"
	case SelUser:
		return "user:" + s.Name
	case SelGroup:
		return "group:" + s.Name
	case SelTag:
		return "tag:" + s.Name
	case SelPeer:
		return "peer:" + s.Name
	case SelSelf:
		return "self"
	case SelCIDR:
		return s.Prefix.String()
	case SelInternet:
		return "internet"
	}
	return "?"
}

// ParseSelector parses a src selector, or a dst host when dst is true
// (which additionally allows "self").
func ParseSelector(raw string, dst bool) (Selector, error) {
	s := strings.TrimSpace(raw)
	switch s {
	case "":
		return Selector{}, fmt.Errorf("empty selector")
	case "*":
		return Selector{Kind: SelAny}, nil
	case "self":
		if !dst {
			return Selector{}, fmt.Errorf("%q is only valid in dst", s)
		}
		return Selector{Kind: SelSelf}, nil
	case "internet":
		if !dst {
			return Selector{}, fmt.Errorf("%q is only valid in dst", s)
		}
		return Selector{Kind: SelInternet}, nil
	}
	if kind, name, ok := strings.Cut(s, ":"); ok {
		if !validLabel(name) {
			return Selector{}, fmt.Errorf("%q: name must be a lowercase label", s)
		}
		switch kind {
		case "user":
			return Selector{Kind: SelUser, Name: name}, nil
		case "group":
			return Selector{Kind: SelGroup, Name: name}, nil
		case "tag":
			return Selector{Kind: SelTag, Name: name}, nil
		case "peer":
			return Selector{Kind: SelPeer, Name: name}, nil
		}
		return Selector{}, fmt.Errorf("%q: unknown selector kind %q (user, group, tag, peer)", s, kind)
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		if !p.Addr().Is4() {
			return Selector{}, fmt.Errorf("%q: only IPv4 prefixes are supported", s)
		}
		return Selector{Kind: SelCIDR, Prefix: p.Masked()}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if !a.Is4() {
			return Selector{}, fmt.Errorf("%q: only IPv4 addresses are supported", s)
		}
		return Selector{Kind: SelCIDR, Prefix: netip.PrefixFrom(a, 32)}, nil
	}
	if validLabel(s) {
		return Selector{Kind: SelUser, Name: s}, nil
	}
	return Selector{}, fmt.Errorf("%q is not a selector", s)
}

// validLabel accepts lowercase DNS-label-like names.
func validLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}

// PortRange is an inclusive port interval.
type PortRange struct {
	Lo, Hi uint16
}

// AllPorts is the "*" port range.
var AllPorts = PortRange{Lo: 1, Hi: 65535}

// ParsePorts parses "*", "22", "22,443", "8000-8100" and combinations.
// Ranges are sorted and merged.
func ParsePorts(raw string) ([]PortRange, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("empty port list")
	}
	if s == "*" {
		return []PortRange{AllPorts}, nil
	}
	var out []PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = parsePort(hi); err != nil {
				return nil, err
			}
			if b < a {
				return nil, fmt.Errorf("port range %q is reversed", part)
			}
		}
		out = append(out, PortRange{Lo: a, Hi: b})
	}
	return mergeRanges(out), nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("port %q must be 1-65535", s)
	}
	return uint16(n), nil
}

// mergeRanges sorts and coalesces overlapping or adjacent ranges.
func mergeRanges(in []PortRange) []PortRange {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i].Lo < in[j].Lo })
	out := []PortRange{in[0]}
	for _, r := range in[1:] {
		last := &out[len(out)-1]
		if int(r.Lo) <= int(last.Hi)+1 {
			if r.Hi > last.Hi {
				last.Hi = r.Hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// Dst is one parsed dst entry: a host selector and its ports.
type Dst struct {
	Host  Selector
	Ports []PortRange
}

// ParseDst parses "host:ports" where host is a dst selector.
func ParseDst(raw string) (Dst, error) {
	s := strings.TrimSpace(raw)
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return Dst{}, fmt.Errorf("%q must be host:ports", s)
	}
	host, err := ParseSelector(s[:i], true)
	if err != nil {
		return Dst{}, err
	}
	ports, err := ParsePorts(s[i+1:])
	if err != nil {
		return Dst{}, fmt.Errorf("%q: %w", s, err)
	}
	return Dst{Host: host, Ports: ports}, nil
}

// Protocols.
const (
	ProtoAny  = "any"
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoICMP = "icmp"
)

// ParseProto normalises the proto field; empty means any.
func ParseProto(raw string) (string, error) {
	switch p := strings.ToLower(strings.TrimSpace(raw)); p {
	case "", ProtoAny:
		return ProtoAny, nil
	case ProtoTCP, ProtoUDP, ProtoICMP:
		return p, nil
	default:
		return "", fmt.Errorf("proto %q must be tcp, udp, icmp or any", raw)
	}
}
