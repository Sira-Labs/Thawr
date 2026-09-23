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

	if err := CheckNotRunning(d.opts.Socket); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("CheckNotRunning: %v, want ErrAlreadyRunning", err)
	}
	_, err := NewDaemon(DaemonOptions{StateDir: dirB, Socket: d.opts.Socket})
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second daemon: %v, want ErrAlreadyRunning", err)
	}
	if _, err := lc.Status(context.Background()); err != nil {
		t.Fatalf("first daemon lost its socket: %v", err)
	}
}

// TestInstanceLock: the lock settles two clients that start together,
// when neither serves the socket yet, and is free again after Close.
func TestInstanceLock(t *testing.T) {
	socket := shortSocket(t)
	if err := CheckNotRunning(socket); err != nil {
		t.Fatalf("nobody listens yet: %v", err)
	}
	first, err := lockInstance(socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockInstance(socket); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second lock: %v, want ErrAlreadyRunning", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := lockInstance(socket)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	_ = second.Close()
}

// TestDaemonMovesOffTakenPort: a stored listen port another process
// holds, on either address family, is replaced at start and persisted,
// so the device comes up instead of failing every configure; a free
// stored port is kept across restarts.
func TestDaemonMovesOffTakenPort(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			var lc net.ListenConfig
			blocker, err := lc.ListenPacket(context.Background(), network, ":0")
			if err != nil {
				t.Skipf("cannot bind %s here: %v", network, err)
			}
			defer func() { _ = blocker.Close() }()
			taken := blocker.LocalAddr().(*net.UDPAddr).Port

			cp := newControlPlane(t)
			dir := t.TempDir()
			st := cp.enrol(dir, "a")
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

			d, _, stop = startDaemon(t, dir)
			defer stop()
			if d.state.ListenPort != got {
				t.Errorf("free port %d replaced by %d on restart", got, d.state.ListenPort)
			}
		})
	}
}
