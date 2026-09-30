package client

import (
	"fmt"
	"os"

	"github.com/sira-labs/thawr/internal/fsperm"
)

// restrictToAdmins secures the state directory; see fsperm.
func restrictToAdmins(path string) error { return fsperm.RestrictToAdmins(path) }

// secureSocket limits the socket to SYSTEM and Administrators: an
// AF_UNIX connect needs write access to the socket file, and whatever
// the directory grants would otherwise let any local user stop the
// client or rotate its key. Windows has no thawr group to hand it to.
func secureSocket(path string) error {
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // group access is intended
		return fmt.Errorf("client: chmod socket: %w", err)
	}
	return restrictToAdmins(path)
}
