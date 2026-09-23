package client

import (
	"context"
	"errors"
	"net"
	"testing"
)

// TestDaemonRefusesSecondInstance: a second client on the same socket
// fails before it touches the device, instead of taking the socket
// over and racing the first one for the WireGuard port.
func TestDaemonRefusesSecondInstance(t *testing.T) {
	cp := newControlPlane(t)
	dirA, dirB := t.TempDir(), t.TempDir()
	cp.enrol(dirA, "a")
	cp.enrol(dirB, "b")
	d, _, stop := startDaemon(t, dirA)
	defer stop()
	lc := NewLocalClient(d.opts.Socket)
	waitStatus(t, lc, "first daemon serving", func(Status) bool { return true })

	_, err := NewDaemon(DaemonOptions{StateDir: dirB, Socket: d.opts.Socket})
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second daemon: %v, want ErrAlreadyRunning", err)
	}
	if _, err := lc.Status(context.Background()); err != nil {
		t.Fatalf("first daemon lost its socket: %v", err)
	}
}

// TestDaemonMovesOffTakenPort: a stored listen port another process
// holds is replaced at start and persisted, so the device comes up
// instead of failing every configure; a free stored port is kept.
func TestDaemonMovesOffTakenPort(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	st := cp.enrol(dir, "a")
	var lc net.ListenConfig
	blocker, err := lc.ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Close() }()
	taken := blocker.LocalAddr().(*net.UDPAddr).Port
	st.ListenPort = taken
	if err := SaveState(dir, st); err != nil {
		t.Fatal(err)
	}

	d, fake, stop := startDaemon(t, dir)
	waitApplied(t, d, func(NetMap) bool { return true })
	got := d.state.ListenPort
	if got == taken || got == 0 {
		t.Fatalf("listen port %d not moved off the taken %d", got, taken)
	}
	if cfg, ok := fake.Last(); !ok || cfg.ListenPort != got {
		t.Errorf("device configured with %d, state says %d", cfg.ListenPort, got)
	}
	if saved, _ := LoadState(dir); saved.ListenPort != got {
		t.Errorf("state not persisted: %d, want %d", saved.ListenPort, got)
	}
	stop()

	// The free port survives a restart.
	d, _, stop = startDaemon(t, dir)
	defer stop()
	if d.state.ListenPort != got {
		t.Errorf("free port %d replaced by %d on restart", got, d.state.ListenPort)
	}
}
