package svc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeRunner records every command and answers from a script keyed by
// the joined command line.
type fakeRunner struct {
	calls   []string
	outputs map[string]string
	fail    map[string]error
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if err, ok := f.fail[line]; ok {
		return []byte(f.outputs[line]), err
	}
	return []byte(f.outputs[line]), nil
}

func sampleService() Service {
	return Service{
		Name: "thawr-client", Description: "Thawr node client", Exec: "/usr/local/bin/thawr",
		Args:           []string{"client", "up", "--state-dir", "/var/lib/thawr/client", "--socket", "/var/run/thawr/client.sock", "--interface", "thawr0", "--log-level", "info"},
		ReadWritePaths: []string{"/var/lib/thawr/client", "/var/run/thawr"},
	}
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("THAWR_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (set THAWR_UPDATE_GOLDEN=1 to create it)", err)
	}
	if w := strings.ReplaceAll(string(want), "\r\n", "\n"); got != w {
		t.Errorf("%s differs from golden:\n%s", name, got)
	}
}

func TestSystemdUnitRender(t *testing.T) {
	s := Service{Name: "thawr-server", Description: "Thawr control server", Exec: "/usr/local/bin/thawr",
		Args: []string{"server", "--config", "/etc/thawr/server.yaml"}, ReadWritePaths: []string{"/var/lib/thawr"}, Reload: true}
	checkGolden(t, "thawr-server.service", RenderSystemdUnit(s))
	unit := RenderSystemdUnit(Service{Name: "x", Exec: "/opt/my tools/thawr", Args: []string{"client", "up", "--name", `a"b`, "--state-dir", "/tmp/$HOME"}})
	if !strings.Contains(unit, `ExecStart="/opt/my tools/thawr" client up --name "a\"b" --state-dir "/tmp/$$HOME"`) {
		t.Errorf("quoting:\n%s", unit)
	}
	if strings.Contains(RenderSystemdUnit(Service{Name: "x", Exec: "/bin/x"}), "ExecReload") {
		t.Error("ExecReload without Reload")
	}
}

func TestLaunchdPlistRender(t *testing.T) {
	s := sampleService()
	checkGolden(t, "thawr-client.plist", RenderLaunchdPlist(s, "/Library/Logs/Thawr"))
	got := RenderLaunchdPlist(Service{Name: "x", Exec: "/bin/x", Args: []string{"--name", "a<b&c"}}, "/l")
	if !strings.Contains(got, "<string>a&lt;b&amp;c</string>") {
		t.Errorf("xml escaping:\n%s", got)
	}
}

func TestServiceFilesNoSecrets(t *testing.T) {
	// The install path receives only what the daemon needs to find its
	// state; anything that looks like a credential in Args is a bug in
	// the caller, and this test documents the rendered files as
	// secret-free for the standard services.
	for _, s := range []Service{sampleService(),
		{Name: "thawr-server", Exec: "/usr/local/bin/thawr", Args: []string{"server", "--config", "/etc/thawr/server.yaml"}, Reload: true}} {
		for name, text := range map[string]string{"unit": RenderSystemdUnit(s), "plist": RenderLaunchdPlist(s, "/Library/Logs/Thawr")} {
			for _, bad := range []string{"--token", "thawr_", "node_secret", "PrivateKey", "password"} {
				if strings.Contains(text, bad) {
					t.Errorf("%s for %s contains %q", name, s.Name, bad)
				}
			}
		}
	}
}

func TestSystemdInstallCommands(t *testing.T) {
	root := t.TempDir()
	fr := &fakeRunner{outputs: map[string]string{"systemctl is-active thawr-client": "active\n"}}
	m := newSystemd(Options{Runner: fr.run, Root: root})
	ctx := context.Background()
	if st, err := m.Status(ctx, "thawr-client"); err != nil || st != Absent {
		t.Fatalf("status before install: %v %v", st, err)
	}
	files, err := m.Install(ctx, sampleService())
	if err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(root, "etc", "systemd", "system", "thawr-client.service")
	if len(files) != 1 || files[0] != unit {
		t.Errorf("files: %v", files)
	}
	if fi, err := os.Stat(unit); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644) {
		t.Errorf("unit file: %v %v", fi, err)
	}
	if err := m.Start(ctx, "thawr-client"); err != nil {
		t.Fatal(err)
	}
	if st, err := m.Status(ctx, "thawr-client"); err != nil || st != Running {
		t.Errorf("status running: %v %v", st, err)
	}
	fr.outputs["systemctl is-active thawr-client"] = "inactive\n"
	fr.fail = map[string]error{"systemctl is-active thawr-client": errors.New("exit status 3")}
	if st, err := m.Status(ctx, "thawr-client"); err != nil || st != Stopped {
		t.Errorf("status stopped: %v %v", st, err)
	}
	if err := m.Stop(ctx, "thawr-client"); err != nil {
		t.Fatal(err)
	}
	if err := m.Uninstall(ctx, "thawr-client"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unit); !errors.Is(err, os.ErrNotExist) {
		t.Error("unit not removed")
	}
	if err := m.Uninstall(ctx, "thawr-client"); err != nil {
		t.Errorf("second uninstall: %v", err)
	}
	want := []string{
		"systemctl daemon-reload", "systemctl enable thawr-client", "systemctl start thawr-client",
		"systemctl is-active thawr-client", "systemctl is-active thawr-client", "systemctl stop thawr-client",
		"systemctl disable thawr-client", "systemctl daemon-reload",
	}
	if strings.Join(fr.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands:\n%s\nwant:\n%s", strings.Join(fr.calls, "\n"), strings.Join(want, "\n"))
	}
}

func TestLaunchdInstallCommands(t *testing.T) {
	root := t.TempDir()
	fr := &fakeRunner{outputs: map[string]string{}, fail: map[string]error{}}
	m := newLaunchd(Options{Runner: fr.run, Root: root})
	ctx := context.Background()
	files, err := m.Install(ctx, sampleService())
	if err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(root, "Library", "LaunchDaemons", "thawr-client.plist")
	if len(files) != 1 || files[0] != plist {
		t.Errorf("files: %v", files)
	}
	if _, err := os.Stat(filepath.Join(root, "Library", "Logs", "Thawr")); err != nil {
		t.Errorf("log dir: %v", err)
	}
	if len(fr.calls) != 0 {
		t.Errorf("install ran %v; it must only write files", fr.calls)
	}
	// Not loaded yet: Stopped, then Running once launchctl knows it.
	fr.fail["launchctl print system/thawr-client"] = errors.New("exit status 113")
	if st, err := m.Status(ctx, "thawr-client"); err != nil || st != Stopped {
		t.Errorf("status before start: %v %v", st, err)
	}
	if err := m.Start(ctx, "thawr-client"); err != nil {
		t.Fatal(err)
	}
	delete(fr.fail, "launchctl print system/thawr-client")
	fr.outputs["launchctl print system/thawr-client"] = "system/thawr-client = {\n\tstate = running\n}\n"
	if st, err := m.Status(ctx, "thawr-client"); err != nil || st != Running {
		t.Errorf("status running: %v %v", st, err)
	}
	// A second Start on a loaded job falls back to kickstart.
	fr.fail["launchctl bootstrap system "+plist] = errors.New("exit status 37")
	if err := m.Start(ctx, "thawr-client"); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(ctx, "thawr-client"); err != nil {
		t.Fatal(err)
	}
	if err := m.Uninstall(ctx, "thawr-client"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plist); !errors.Is(err, os.ErrNotExist) {
		t.Error("plist not removed")
	}
	if st, err := m.Status(ctx, "thawr-client"); err != nil || st != Absent {
		t.Errorf("status after uninstall: %v %v", st, err)
	}
	want := []string{
		"launchctl print system/thawr-client", "launchctl bootstrap system " + plist, "launchctl print system/thawr-client",
		"launchctl bootstrap system " + plist, "launchctl kickstart -k system/thawr-client",
		"launchctl bootout system/thawr-client", "launchctl bootout system/thawr-client",
	}
	if strings.Join(fr.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands:\n%s\nwant:\n%s", strings.Join(fr.calls, "\n"), strings.Join(want, "\n"))
	}
	if !strings.HasPrefix(m.Logs("thawr-client"), "tail -f ") || !strings.HasPrefix(newSystemd(Options{}).Logs("x"), "journalctl -u x") {
		t.Error("logs hint")
	}
}

func TestInvalidServiceNames(t *testing.T) {
	m := newSystemd(Options{Runner: (&fakeRunner{}).run, Root: t.TempDir()})
	for _, name := range []string{"", "../etc", "Thawr", "a b", "x.service"} {
		if _, err := m.Install(context.Background(), Service{Name: name, Exec: "/bin/x"}); err == nil {
			t.Errorf("%q accepted", name)
		}
		if _, err := m.Status(context.Background(), name); err == nil {
			t.Errorf("%q accepted by Status", name)
		}
	}
	if _, err := m.Install(context.Background(), Service{Name: "ok"}); err == nil {
		t.Error("empty Exec accepted")
	}
}

// TestArgsRoundTrip: what Install writes, Args reads back unchanged,
// quotes, spaces, dollars and XML metacharacters included.
func TestArgsRoundTrip(t *testing.T) {
	args := []string{"client", "up", "--socket", "/var/run/my thawr/c.sock", "--name", `a"b\c`, "--state-dir", "/tmp/$HOME", "--x", "a<b&c", ""}
	s := Service{Name: "thawr-client", Exec: "/opt/my tools/thawr", Args: args}
	root := t.TempDir()
	r := &fakeRunner{}
	managers := map[string]Manager{
		"systemd": newSystemd(Options{Root: filepath.Join(root, "s"), Runner: r.run}),
		"launchd": newLaunchd(Options{Root: filepath.Join(root, "l"), Runner: r.run}),
	}
	for name, m := range managers {
		if _, err := m.Install(context.Background(), s); err != nil {
			t.Fatalf("%s install: %v", name, err)
		}
		got, err := m.Args(context.Background(), s.Name)
		if err != nil {
			t.Fatalf("%s args: %v", name, err)
		}
		if strings.Join(got, "\x00") != strings.Join(args, "\x00") || len(got) != len(args) {
			t.Errorf("%s args = %q, want %q", name, got, args)
		}
		if _, err := m.Args(context.Background(), "thawr-absent"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s args of an absent service: %v", name, err)
		}
	}
}

func TestSplitSystemdCommand(t *testing.T) {
	for _, bad := range []string{`/bin/x "open`} {
		if _, err := splitSystemdCommand(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	got, err := splitSystemdCommand("  /bin/x\ta  b ")
	if err != nil || strings.Join(got, ",") != "/bin/x,a,b" {
		t.Errorf("whitespace: %q %v", got, err)
	}
}
