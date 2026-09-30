package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	winsvc "golang.org/x/sys/windows/svc"

	"github.com/sira-labs/thawr/internal/svc"
)

// redirectServiceOutput sends stdout and stderr to the service's log
// file when this process runs as a Windows service: the control manager
// keeps no output, so log lines, the final error and a panic would be
// lost. The file is appended to and not rotated, like the launchd log.
func redirectServiceOutput(args []string) error {
	isService, err := winsvc.IsWindowsService()
	if err != nil || !isService {
		return nil
	}
	name := serviceNameFor(args)
	if name == "" {
		return nil
	}
	path := svc.LogPath(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // logs hold no secrets and are meant to be read
		return fmt.Errorf("create log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec // path is built from a fixed service name
	if err != nil {
		return fmt.Errorf("open service log: %w", err)
	}
	// The runtime writes a panic through the standard handle, not
	// os.Stderr, so both are pointed at the file.
	for _, std := range []uint32{windows.STD_OUTPUT_HANDLE, windows.STD_ERROR_HANDLE} {
		if err := windows.SetStdHandle(std, windows.Handle(f.Fd())); err != nil {
			return fmt.Errorf("redirect service output: %w", err)
		}
	}
	os.Stdout, os.Stderr = f, f
	return nil
}

// serviceNameFor is the service a command line runs as: the name
// `thawr server install` or `thawr client install` registered.
func serviceNameFor(args []string) string {
	if len(args) == 0 {
		return ""
	}
	switch args[0] {
	case "server":
		return serviceServer
	case "client":
		return serviceClient
	}
	return ""
}
