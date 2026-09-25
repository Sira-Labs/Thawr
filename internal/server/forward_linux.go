package server

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/sira-labs/thawr/internal/wg"
)

// enableForwarding lets the kernel forward packets that arrive on the
// hub interface back out of it, which is how a phone reaches a mesh
// peer. Per-interface forwarding is enough: Linux consults the ingress
// device's flag. Hosts running Docker also carry a FORWARD chain that
// drops by default; the hub opens it for its own interface and the
// returned function closes it again.
func enableForwarding(iface string, log *slog.Logger) (undo func()) {
	undo = func() {}
	path := filepath.Join("/proc/sys/net/ipv4/conf", iface, "forwarding")
	if err := os.WriteFile(path, []byte("1\n"), 0); err != nil {
		log.Warn("hub forwarding not enabled; mobile peers cannot reach the mesh", "path", path, "err", fmt.Errorf("write: %w", err))
		return undo
	}
	log.Debug("hub forwarding enabled", "interface", iface)
	chains, remove, err := wg.AllowForward(iface)
	switch {
	case err != nil:
		log.Warn("could not open the host's forward chain for the hub; if Docker runs here, add `iptables -I DOCKER-USER -i "+iface+" -o "+iface+" -j ACCEPT`", "err", err)
	case chains > 0:
		log.Info("host forward chain opened for the hub interface", "interface", iface, "chains", chains)
		undo = func() {
			if err := remove(); err != nil {
				log.Warn("could not remove the hub's forward accept rule", "err", err)
			}
		}
	}
	return undo
}
