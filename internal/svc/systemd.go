package svc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// systemdDir is where locally installed units live.
const systemdDir = "/etc/systemd/system"

// systemd drives systemctl and writes units under Root.
type systemd struct{ opts Options }

func newSystemd(opts Options) *systemd { return &systemd{opts: opts.withDefaults()} }

func (m *systemd) unitPath(name string) string {
	return filepath.Join(m.opts.Root, systemdDir, name+".service")
}

func (m *systemd) run(ctx context.Context, args ...string) ([]byte, error) {
	return m.opts.Runner(ctx, "systemctl", args...)
}

// Install writes the unit, reloads systemd and enables the unit for
// boot without starting it.
func (m *systemd) Install(ctx context.Context, s Service) ([]string, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	path := m.unitPath(s.Name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // system directories are world-readable by convention
		return nil, fmt.Errorf("svc: %w", err)
	}
	if err := os.WriteFile(path, []byte(RenderSystemdUnit(s)), 0o644); err != nil { //nolint:gosec // unit files are world-readable by convention and contain no secrets
		return nil, fmt.Errorf("svc: write unit: %w", err)
	}
	if _, err := m.run(ctx, "daemon-reload"); err != nil {
		return []string{path}, err
	}
	if _, err := m.run(ctx, "enable", s.Name); err != nil {
		return []string{path}, err
	}
	m.opts.Logger.Info("systemd unit installed", "unit", path)
	return []string{path}, nil
}

func (m *systemd) Start(ctx context.Context, name string) error {
	if err := validName(name); err != nil {
		return err
	}
	_, err := m.run(ctx, "start", name)
	return err
}

func (m *systemd) Stop(ctx context.Context, name string) error {
	if err := validName(name); err != nil {
		return err
	}
	_, err := m.run(ctx, "stop", name)
	return err
}

// Uninstall disables the unit, removes its file and reloads systemd.
// A unit that is already gone is not an error.
func (m *systemd) Uninstall(ctx context.Context, name string) error {
	if err := validName(name); err != nil {
		return err
	}
	path := m.unitPath(name)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if _, err := m.run(ctx, "disable", name); err != nil {
		m.opts.Logger.Warn("systemctl disable failed, removing the unit anyway", "unit", name, "err", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("svc: remove unit: %w", err)
	}
	_, err := m.run(ctx, "daemon-reload")
	return err
}

// Status is Absent without a unit file, Running when systemctl reports
// the unit active, Stopped otherwise (is-active exits non-zero for
// inactive and failed units, which is not an error here).
func (m *systemd) Status(ctx context.Context, name string) (State, error) {
	if err := validName(name); err != nil {
		return "", err
	}
	if _, err := os.Stat(m.unitPath(name)); errors.Is(err, os.ErrNotExist) {
		return Absent, nil
	} else if err != nil {
		return "", fmt.Errorf("svc: %w", err)
	}
	out, err := m.run(ctx, "is-active", name)
	state := strings.TrimSpace(string(out))
	if state == "active" || state == "activating" {
		return Running, nil
	}
	if err != nil && state == "" {
		return "", err
	}
	return Stopped, nil
}

// Args reads the ExecStart line of the installed unit.
func (m *systemd) Args(_ context.Context, name string) ([]string, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(m.unitPath(name))
	if err != nil {
		return nil, fmt.Errorf("svc: read unit: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if cmd, ok := strings.CutPrefix(line, "ExecStart="); ok {
			words, err := splitSystemdCommand(cmd)
			if err != nil {
				return nil, fmt.Errorf("svc: unit %s: ExecStart %q: %w", name, cmd, err)
			}
			if len(words) == 0 {
				return nil, fmt.Errorf("svc: unit %s has an empty ExecStart line", name)
			}
			return words[1:], nil
		}
	}
	return nil, fmt.Errorf("svc: unit %s has no ExecStart line", name)
}

func (m *systemd) Logs(name string) string { return "journalctl -u " + name + " -f" }

// RenderSystemdUnit renders the unit file for s. The process runs as
// root (it creates WireGuard interfaces) inside a read-only view of the
// system except for its own directories and /run/thawr.
func RenderSystemdUnit(s Service) string {
	var b strings.Builder
	b.WriteString("[Unit]\n")
	fmt.Fprintf(&b, "Description=%s\n", s.Description)
	b.WriteString("After=network-online.target\nWants=network-online.target\n\n[Service]\n")
	fmt.Fprintf(&b, "ExecStart=%s\n", systemdCommand(s.Exec, s.Args))
	if s.Reload {
		b.WriteString("ExecReload=/bin/kill -HUP $MAINPID\n")
	}
	b.WriteString("Restart=on-failure\nRestartSec=2\nRuntimeDirectory=thawr\n")
	b.WriteString("NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n")
	if len(s.ReadWritePaths) > 0 {
		quoted := make([]string, 0, len(s.ReadWritePaths))
		for _, p := range s.ReadWritePaths {
			quoted = append(quoted, systemdQuote(p))
		}
		fmt.Fprintf(&b, "ReadWritePaths=%s\n", strings.Join(quoted, " "))
	}
	b.WriteString("LimitNOFILE=65536\n\n[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}

// systemdCommand joins an ExecStart line, quoting where systemd needs it.
func systemdCommand(exe string, args []string) string {
	parts := []string{systemdQuote(exe)}
	for _, a := range args {
		parts = append(parts, systemdQuote(a))
	}
	return strings.Join(parts, " ")
}

// systemdQuote wraps a word in double quotes when it contains
// whitespace, quotes or backslashes, escaping the latter two.
func systemdQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\"'\\$") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `$$`)
	return `"` + r.Replace(s) + `"`
}

// splitSystemdCommand reverses systemdCommand: it splits on whitespace
// outside double quotes and undoes the escapes systemdQuote adds.
func splitSystemdCommand(line string) ([]string, error) {
	var (
		words         []string
		cur           strings.Builder
		inWord, quote bool
	)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote && c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
		case quote && c == '"':
			quote = false
		case c == '$' && i+1 < len(line) && line[i+1] == '$':
			i++
			cur.WriteByte('$')
			inWord = true
		case !quote && c == '"':
			quote, inWord = true, true
		case !quote && (c == ' ' || c == '\t'):
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if quote {
		return nil, errors.New("unterminated quote")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}
