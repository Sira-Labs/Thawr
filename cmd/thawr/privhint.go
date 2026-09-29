package main

import (
	"errors"
	"fmt"
	"io/fs"
	"runtime"
)

// elevateHint says how to run a command with the rights it lacks.
func elevateHint() string {
	if runtime.GOOS == "windows" {
		return "run it from an elevated (Administrator) prompt"
	}
	return "run it with sudo"
}

// permissionError turns a permission failure on a local socket or state
// file into exit 2 with the way out. Other errors pass through, so the
// caller keeps its own wording for them.
func permissionError(err error) error {
	var ee *exitError
	if err == nil || !errors.Is(err, fs.ErrPermission) || errors.As(err, &ee) {
		return err
	}
	return &exitError{code: exitConfigError, err: fmt.Errorf("%w; %s", err, elevateHint())}
}

// socketPermission is the error for a client socket this user may not
// open: the daemon may well be running, this user cannot ask it.
func socketPermission(socket string) error {
	return &exitError{code: exitConfigError, err: fmt.Errorf("no permission to use the client socket %s; %s", socket, elevateHint())}
}
