package client

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// addrInUse reports a bind refused because the port is taken.
func addrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, windows.WSAEADDRINUSE)
}
