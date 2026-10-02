package flock

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestTryLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	first, err := TryLock(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := TryLock(path); !errors.Is(err, ErrHeld) {
		t.Fatalf("second lock while held: got %v, want ErrHeld", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	again, err := TryLock(path)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	_ = again.Close()
}
