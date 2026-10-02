//go:build !windows

package client

import (
	"errors"
	"syscall"
)

// addrInUse reports a bind refused because the port is taken.
func addrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
