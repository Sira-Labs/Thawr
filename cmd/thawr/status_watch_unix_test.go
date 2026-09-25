//go:build !windows

package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/client"
)

// TestStatusWatchStopsOnInterrupt sends SIGINT to the test process, as
// Ctrl-C would, and expects --watch to return nil after one redraw.
func TestStatusWatchStopsOnInterrupt(t *testing.T) {
	sock := fakeDaemon(t, statusFixture())
	var out safeBuffer
	done := make(chan error, 1)
	go func() { done <- watchStatus(context.Background(), &out, client.NewLocalClient(sock), false) }()
	deadline := time.Now().Add(2 * time.Second)
	for out.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("watch returned %v, want nil on Ctrl-C", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watch did not stop on SIGINT")
	}
	if !strings.Contains(out.String(), "\x1b[2J") || !strings.Contains(out.String(), "connected (netmap #42") {
		t.Errorf("watch output: %q", out.String())
	}
}

// safeBuffer is a bytes.Buffer usable from two goroutines.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *safeBuffer) Len() int       { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Len() }
func (s *safeBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
