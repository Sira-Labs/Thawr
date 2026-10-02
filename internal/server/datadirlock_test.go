package server

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDataDirLock: a second server on the same data_dir fails before it
// opens the database, which therefore keeps the first server's state.
func TestDataDirLock(t *testing.T) {
	cfg, dir := testConfig(t)
	first := newHarness(t, cfg)
	first.start(t)
	defer first.stop(t)

	second, _ := testConfig(t)
	second.DataDir = cfg.DataDir
	second.AdminSocket = filepath.Join(dir, "admin2.sock")
	h := newHarness(t, second)
	started := time.Now()
	err := h.runExpectingError(t)
	if !errors.Is(err, ErrDataDirInUse) {
		t.Fatalf("second Run: got %v, want ErrDataDirInUse", err)
	}
	if d := time.Since(started); d > time.Second {
		t.Errorf("second Run took %s to fail", d)
	}
	if _, err := os.Stat(cfg.AdminSocket); err != nil {
		t.Errorf("first server's admin socket disappeared: %v", err)
	}
}
