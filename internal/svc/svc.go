package svc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// State is what a service manager knows about a service.
type State string

// Service states reported by Manager.Status.
const (
	Running State = "running"
	Stopped State = "stopped"
	// Absent means the service is not registered at all.
	Absent State = "absent"
)

// ErrUnsupported is returned by New on platforms without a manager.
var ErrUnsupported = errors.New("svc: no service manager on this platform")

// Service describes one registration. Exec and Args never contain
// secrets: the client enrols before the unit is written and reads its
// state from the 0600 state directory.
type Service struct {
	// Name is the unit, label or service name: thawr-server, thawr-client.
	Name        string
	Description string
	// Exec is the absolute path of the binary.
	Exec string
	Args []string
	// ReadWritePaths are the directories the process writes to; systemd
	// mounts everything else read-only.
	ReadWritePaths []string
	// Reload adds a SIGHUP reload action where the manager supports one.
	Reload bool
}

// Manager registers, starts, stops and removes services.
type Manager interface {
	// Install writes the unit and registers it to start at boot without
	// starting it. It returns the files it wrote.
	Install(ctx context.Context, s Service) (files []string, err error)
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	// Uninstall unregisters the service and removes its unit; it does
	// not stop a running instance first.
	Uninstall(ctx context.Context, name string) error
	Status(ctx context.Context, name string) (State, error)
	// Args returns the arguments the installed service passes to its
	// binary, the binary itself not included, read back from the unit,
	// plist or service entry.
	Args(ctx context.Context, name string) ([]string, error)
	// Logs is the command a user runs to follow the service's output.
	Logs(name string) string
}

// Runner executes a command and returns its combined output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Options configure New. Zero values select the production defaults.
type Options struct {
	// Runner defaults to os/exec.
	Runner Runner
	// Root is prefixed to every absolute path the manager writes (tests).
	Root   string
	Logger *slog.Logger
}

func (o Options) withDefaults() Options {
	if o.Runner == nil {
		o.Runner = execRunner
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return o
}

// execRunner is the production Runner.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // fixed service-manager binaries, arguments built here
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// validName rejects anything that could escape a path or a unit name.
func validName(name string) error {
	if name == "" {
		return errors.New("svc: empty service name")
	}
	for _, r := range name {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-'
		if !ok {
			return fmt.Errorf("svc: service name %q must be lower-case letters, digits and dashes", name)
		}
	}
	return nil
}

func (s Service) validate() error {
	if err := validName(s.Name); err != nil {
		return err
	}
	if s.Exec == "" {
		return fmt.Errorf("svc: service %s has no executable", s.Name)
	}
	return nil
}
