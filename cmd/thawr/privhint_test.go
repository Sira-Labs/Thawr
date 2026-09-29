package main

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

func TestPermissionError(t *testing.T) {
	denied := fmt.Errorf("dial unix /var/run/thawr/client.sock: %w", fs.ErrPermission)
	var ee *exitError
	if err := permissionError(denied); !errors.As(err, &ee) || ee.code != exitConfigError || !strings.Contains(err.Error(), elevateHint()) {
		t.Errorf("permissionError(denied) = %v, want exit %d with %q", err, exitConfigError, elevateHint())
	}
	other := errors.New("connection refused")
	if err := permissionError(other); !errors.Is(err, other) || err.Error() != other.Error() {
		t.Errorf("permissionError(other) = %v, want it unchanged", err)
	}
	// An error that already carries an exit code keeps it.
	coded := &exitError{code: exitNotRunning, err: denied}
	if err := permissionError(coded); !errors.As(err, &ee) || ee.code != exitNotRunning {
		t.Errorf("permissionError(exitError) = %v, want exit %d kept", err, exitNotRunning)
	}
	if permissionError(nil) != nil {
		t.Error("permissionError(nil) is not nil")
	}
}

func TestSocketPermission(t *testing.T) {
	err := socketPermission("/var/run/thawr/client.sock")
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != exitConfigError || !strings.Contains(err.Error(), "/var/run/thawr/client.sock") || !strings.Contains(err.Error(), elevateHint()) {
		t.Errorf("socketPermission = %v", err)
	}
}
