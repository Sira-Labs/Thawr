package control

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/sira-labs/thawr/internal/store"
)

// SanitizeName turns a hostname into a DNS label: lowercase letters,
// digits and hyphens, at most 63 characters, never empty.
func SanitizeName(hostname string) string {
	var b strings.Builder
	lastDash := true // suppress a leading hyphen
	for _, r := range strings.ToLower(hostname) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	name := strings.TrimRight(b.String(), "-")
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-")
	}
	if name == "" {
		return "peer"
	}
	return name
}

// uniqueName returns base if free, else base-2, base-3, ... using one
// query for all candidates.
func uniqueName(ctx context.Context, peers *store.Peers, base string) (string, error) {
	taken, err := peers.NamesWithPrefix(ctx, base)
	if err != nil {
		return "", err
	}
	set := make(map[string]bool, len(taken))
	for _, n := range taken {
		set[n] = true
	}
	if !set[base] {
		return base, nil
	}
	for i := 2; i < 10000; i++ {
		candidate := base + "-" + strconv.Itoa(i)
		if len(candidate) > 63 {
			candidate = base[:63-len("-"+strconv.Itoa(i))] + "-" + strconv.Itoa(i)
		}
		if !set[candidate] {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("control: no free name derived from %q", base)
}
