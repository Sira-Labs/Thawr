//go:build !linux && !darwin

package server

import "log/slog"

// enableForwarding is a no-op outside Linux and macOS: the host's own IP
// forwarding setting decides whether mobile peers reach the mesh.
func enableForwarding(iface string, _ bool, log *slog.Logger) (undo func()) {
	log.Info("hub forwarding is left to the host on this platform; enable IP forwarding for mobile peers", "interface", iface)
	return func() {}
}
