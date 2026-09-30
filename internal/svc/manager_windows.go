package svc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// New returns the Windows service manager adapter.
func New(opts Options) (Manager, error) { return &winsvc{opts: opts.withDefaults()}, nil }

// winsvc talks to the service control manager through x/sys.
type winsvc struct{ opts Options }

// stopTimeout bounds how long Stop waits for the service to end.
const stopTimeout = 15 * time.Second

func (m *winsvc) connect() (*mgr.Mgr, error) {
	c, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("svc: connect to the service manager: %w", err)
	}
	return c, nil
}

// Install creates an auto-start service that restarts 2 s after a
// failure: a crash, or a stop with a non-zero exit code. No file is
// written; the arguments live in the service entry.
func (m *winsvc) Install(_ context.Context, s Service) ([]string, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	c, err := m.connect()
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Disconnect() }()
	svcHandle, err := c.CreateService(s.Name, s.Exec, mgr.Config{
		StartType: mgr.StartAutomatic, DisplayName: s.Name, Description: s.Description, ErrorControl: mgr.ErrorNormal,
	}, s.Args...)
	if err != nil {
		return nil, fmt.Errorf("svc: create service %s: %w", s.Name, err)
	}
	defer func() { _ = svcHandle.Close() }()
	if err := svcHandle.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 2 * time.Second}}, 0); err != nil {
		return nil, fmt.Errorf("svc: set recovery for %s: %w", s.Name, err)
	}
	// The binary reports Stopped with a non-zero exit code when its work
	// fails; without this flag only a crash would trigger the restart.
	if err := svcHandle.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return nil, fmt.Errorf("svc: set recovery on failure exit for %s: %w", s.Name, err)
	}
	m.opts.Logger.Info("windows service installed", "service", s.Name)
	return nil, nil
}

func (m *winsvc) open(name string) (*mgr.Mgr, *mgr.Service, error) {
	if err := validName(name); err != nil {
		return nil, nil, err
	}
	c, err := m.connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := c.OpenService(name)
	if err != nil {
		_ = c.Disconnect()
		return nil, nil, fmt.Errorf("svc: open service %s: %w", name, err)
	}
	return c, s, nil
}

func (m *winsvc) Start(_ context.Context, name string) error {
	c, s, err := m.open(name)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close(); _ = c.Disconnect() }()
	if err := s.Start(); err != nil {
		return fmt.Errorf("svc: start %s: %w", name, err)
	}
	return nil
}

// Stop asks the service to stop and waits until it has.
func (m *winsvc) Stop(ctx context.Context, name string) error {
	c, s, err := m.open(name)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close(); _ = c.Disconnect() }()
	st, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("svc: stop %s: %w", name, err)
	}
	deadline := time.Now().Add(stopTimeout)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("svc: %s did not stop within %s", name, stopTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
		if st, err = s.Query(); err != nil {
			return fmt.Errorf("svc: query %s: %w", name, err)
		}
	}
	return nil
}

// Uninstall deletes the service entry; a missing service is not an error.
func (m *winsvc) Uninstall(_ context.Context, name string) error {
	c, s, err := m.open(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = s.Close(); _ = c.Disconnect() }()
	if err := s.Delete(); err != nil {
		return fmt.Errorf("svc: delete %s: %w", name, err)
	}
	return nil
}

func (m *winsvc) Status(_ context.Context, name string) (State, error) {
	c, s, err := m.open(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return Absent, nil
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = s.Close(); _ = c.Disconnect() }()
	st, err := s.Query()
	if err != nil {
		return "", fmt.Errorf("svc: query %s: %w", name, err)
	}
	if st.State == svc.Running || st.State == svc.StartPending {
		return Running, nil
	}
	return Stopped, nil
}

// Args splits the service's command line back into its arguments.
func (m *winsvc) Args(_ context.Context, name string) ([]string, error) {
	c, s, err := m.open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close(); _ = c.Disconnect() }()
	cfg, err := s.Config()
	if err != nil {
		return nil, fmt.Errorf("svc: read config of %s: %w", name, err)
	}
	argv, err := windows.DecomposeCommandLine(cfg.BinaryPathName)
	if err != nil {
		return nil, fmt.Errorf("svc: parse command line of %s: %w", name, err)
	}
	if len(argv) == 0 {
		return nil, fmt.Errorf("svc: service %s has an empty command line", name)
	}
	return argv[1:], nil
}

func (m *winsvc) Logs(name string) string { return "sc query " + name }
