package server

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// enableForwarding turns on IPv4 forwarding, and IPv6 forwarding with
// the IPv6 overlay, on macOS, which has no per-interface switch:
// without it the kernel drops what the hub hands it for other peers,
// so phones reach only the server itself.
func enableForwarding(iface string, ipv6 bool, log *slog.Logger) (undo func()) {
	settings := []string{"net.inet.ip.forwarding=1"}
	if ipv6 {
		settings = append(settings, "net.inet6.ip6.forwarding=1")
	}
	for _, setting := range settings {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, "sysctl", "-w", setting).CombinedOutput()
		cancel()
		if err != nil {
			log.Warn("hub forwarding not enabled; mobile peers cannot reach the mesh", "interface", iface, "sysctl", setting,
				"err", fmt.Errorf("sysctl: %w: %s", err, strings.TrimSpace(string(out))))
			continue
		}
		log.Debug("hub forwarding enabled", "interface", iface, "sysctl", strings.TrimSpace(string(out)))
	}
	return func() {}
}
