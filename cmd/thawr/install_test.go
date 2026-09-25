package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/svc"
)

// fakeManager records calls and serves a scripted state.
type fakeManager struct {
	state svc.State
	// states overrides state for particular service names.
	states    map[string]svc.State
	calls     *[]string
	installed []svc.Service
	err       error
}

func (m *fakeManager) Install(_ context.Context, s svc.Service) ([]string, error) {
	*m.calls = append(*m.calls, "install")
	m.installed = append(m.installed, s)
	return []string{"/etc/systemd/system/" + s.Name + ".service"}, m.err
}
func (m *fakeManager) Start(_ context.Context, name string) error {
	*m.calls = append(*m.calls, "start "+name)
	return m.err
}
func (m *fakeManager) Stop(_ context.Context, name string) error {
	*m.calls = append(*m.calls, "stop "+name)
	return m.err
}
func (m *fakeManager) Uninstall(_ context.Context, name string) error {
	*m.calls = append(*m.calls, "uninstall "+name)
	return m.err
}
func (m *fakeManager) Status(_ context.Context, name string) (svc.State, error) {
	if st, ok := m.states[name]; ok {
		return st, nil
	}
	return m.state, nil
}
func (m *fakeManager) Logs(name string) string { return "journalctl -u " + name }

// enrolledState is a complete state.json for an already enrolled device.
func enrolledState() client.State {
	return client.State{Server: "https://s", Name: "box", IPv4: "100.64.0.9", PeerID: "p", NodeSecret: "thawr_ns_secret"}
}

// installEnv wires fake dependencies: root, a temp executable outside
// any home directory, a fake manager and a recording enroller.
type installEnv struct {
	deps  cliDeps
	mgr   *fakeManager
	calls []string
	exe   string
	// dirs records every directory the install created.
	dirs []string
}

func newInstallEnv(t *testing.T) *installEnv {
	t.Helper()
	env := &installEnv{exe: filepath.Join(t.TempDir(), "thawr")}
	if runtime.GOOS == "windows" {
		env.exe += ".exe"
	}
	if err := os.WriteFile(env.exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	env.mgr = &fakeManager{state: svc.Absent, calls: &env.calls}
	env.deps = cliDeps{
		newManager: func(svc.Options) (svc.Manager, error) { return env.mgr, nil },
		isRoot:     func() bool { return true },
		executable: func() (string, error) { return env.exe, nil },
		homeDir:    func() (string, error) { return filepath.Join(t.TempDir(), "home"), nil },
		enroll: func(_ context.Context, o client.Options) (client.State, error) {
			env.calls = append(env.calls, "enroll "+o.Server)
			st := client.State{Server: o.Server, Name: "box", IPv4: "100.64.0.9", PeerID: "p", NodeSecret: "thawr_ns_secret"}
			return st, client.SaveState(o.StateDir, st)
		},
		mkdirAll: func(dir string, _ os.FileMode) error { env.dirs = append(env.dirs, dir); return nil },
	}
	return env
}

func (env *installEnv) run(t *testing.T, args ...string) (out, errOut string, code int) {
	t.Helper()
	var o, e bytes.Buffer
	root := newRootCmdWithDeps(&o, &e, env.deps)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	var ee *exitError
	switch {
	case errors.As(err, &ee):
		code = ee.code
	case err != nil:
		code = 1
	}
	if err != nil {
		e.WriteString(err.Error())
	}
	return o.String(), e.String(), code
}

func TestInstallRequiresRoot(t *testing.T) {
	env := newInstallEnv(t)
	env.deps.isRoot = func() bool { return false }
	for _, args := range [][]string{{"server", "install"}, {"server", "uninstall"}, {"client", "install"}, {"client", "uninstall"}} {
		_, errOut, code := env.run(t, args...)
		if code != exitConfigError || !strings.Contains(errOut, "run as root") {
			t.Errorf("%v: code %d, %q", args, code, errOut)
		}
	}
	if len(env.calls) != 0 {
		t.Errorf("calls without root: %v", env.calls)
	}
}

func TestInstallRefusesBadBinaries(t *testing.T) {
	env := newInstallEnv(t)
	dir := t.TempDir()
	cases := map[string][]string{
		"relative":    {"--bin", "bin/thawr"},
		"missing":     {"--bin", filepath.Join(dir, "nope")},
		"directory":   {"--bin", dir},
		"unsupported": nil,
	}
	for name, extra := range cases {
		e := env
		if name == "unsupported" {
			e = newInstallEnv(t)
			e.deps.newManager = func(svc.Options) (svc.Manager, error) { return nil, svc.ErrUnsupported }
			e.deps.enroll = env.deps.enroll
		}
		args := append([]string{"client", "install", "--state-dir", t.TempDir(), "--server", "https://s", "--token", "thawr_t"}, extra...)
		if _, errOut, code := e.run(t, args...); code != exitConfigError {
			t.Errorf("%s: code %d, %q", name, code, errOut)
		}
	}
	if len(env.mgr.installed) != 0 {
		t.Errorf("installed despite bad binary: %+v", env.mgr.installed)
	}
	// The running binary is refused inside the home directory unless
	// --bin says so explicitly.
	home := t.TempDir()
	env.deps.homeDir = func() (string, error) { return home, nil }
	inHome := filepath.Join(home, "go", "bin", "thawr")
	if err := os.MkdirAll(filepath.Dir(inHome), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inHome, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	env.deps.executable = func() (string, error) { return inHome, nil }
	if _, errOut, code := env.run(t, "client", "install", "--state-dir", t.TempDir(), "--server", "https://s", "--token", "thawr_t"); code != exitConfigError || !strings.Contains(errOut, "home directory") {
		t.Errorf("home: code %d, %q", code, errOut)
	}
	if _, _, code := env.run(t, "client", "install", "--state-dir", t.TempDir(), "--server", "https://s", "--token", "thawr_t", "--bin", inHome); code != 0 {
		t.Errorf("explicit --bin in home refused: %d", code)
	}
}

func TestClientInstallEnrolsBeforeWritingUnit(t *testing.T) {
	env := newInstallEnv(t)
	stateDir := t.TempDir()
	sock := filepath.Join(t.TempDir(), "c.sock")
	out, errOut, code := env.run(t, "client", "install", "--state-dir", stateDir, "--socket", sock,
		"--server", "https://vpn.example.com", "--token", "thawr_secret_token", "--fingerprint", "sha256:ab", "--interface", "utun")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got := strings.Join(env.calls, ","); got != "enroll https://vpn.example.com,install,start thawr-client" {
		t.Errorf("order: %s", got)
	}
	s := env.mgr.installed[0]
	if realExe, _ := filepath.EvalSymlinks(env.exe); s.Name != serviceClient || s.Exec != realExe {
		t.Errorf("service: %+v (exe %s)", s, realExe)
	}
	joined := strings.Join(s.Args, " ")
	for _, bad := range []string{"thawr_secret_token", "--token", "thawr_ns_secret", "--server"} {
		if strings.Contains(joined, bad) {
			t.Errorf("service args carry %q: %s", bad, joined)
		}
	}
	for _, want := range []string{"client up", "--state-dir " + stateDir, "--socket " + sock, "--interface utun", "--log-level info", "--dns on"} {
		if !strings.Contains(joined, want) {
			t.Errorf("service args lack %q: %s", want, joined)
		}
	}
	if len(s.ReadWritePaths) != 2 || s.ReadWritePaths[0] != stateDir {
		t.Errorf("rw paths: %v", s.ReadWritePaths)
	}
	if !strings.Contains(out, "thawr-client started and enabled at boot") || !strings.Contains(out, "journalctl -u thawr-client") {
		t.Errorf("output: %s", out)
	}
	if _, err := client.LoadState(stateDir); err != nil {
		t.Errorf("state not saved: %v", err)
	}
}

func TestClientInstallRefusesHubHost(t *testing.T) {
	env := newInstallEnv(t)
	env.mgr.states = map[string]svc.State{serviceServer: svc.Running}
	_, errOut, code := env.run(t, "client", "install", "--state-dir", t.TempDir(), "--server", "https://s", "--token", "thawr_t")
	if code != exitConfigError || !strings.Contains(errOut, "already a peer") {
		t.Errorf("code %d: %s", code, errOut)
	}
	if len(env.calls) != 0 {
		t.Errorf("enrolled or installed despite the hub: %v", env.calls)
	}
}

func TestClientInstallAlreadyInstalledAndEnrolled(t *testing.T) {
	env := newInstallEnv(t)
	stateDir := t.TempDir()
	if err := client.SaveState(stateDir, enrolledState()); err != nil {
		t.Fatal(err)
	}
	// Enrolled, not installed: no token needed, no enrol call.
	out, errOut, code := env.run(t, "client", "install", "--state-dir", stateDir, "--no-start")
	if code != 0 || !strings.Contains(out, "not started") {
		t.Fatalf("code %d: %s %s", code, out, errOut)
	}
	if got := strings.Join(env.calls, ","); got != "install" {
		t.Errorf("calls: %s", got)
	}
	// Installed: reported, nothing changed, exit 0.
	env.mgr.states = map[string]svc.State{serviceClient: svc.Running}
	env.calls = nil
	out, _, code = env.run(t, "client", "install", "--state-dir", stateDir)
	if code != 0 || !strings.Contains(out, "already installed (running)") || len(env.calls) != 0 {
		t.Errorf("code %d, calls %v: %s", code, env.calls, out)
	}
	// Not enrolled and no token: usage error before anything runs.
	env.mgr.states = nil
	if _, errOut, code := env.run(t, "client", "install", "--state-dir", t.TempDir()); code != exitConfigError || !strings.Contains(errOut, "--server and --token") {
		t.Errorf("code %d: %s", code, errOut)
	}
}

func TestServerInstallWritesMinimalConfig(t *testing.T) {
	env := newInstallEnv(t)
	cfgPath := filepath.Join(t.TempDir(), "etc", "thawr", "server.yaml")
	out, errOut, code := env.run(t, "server", "install", "--config", cfgPath, "--public-addr", "vpn.example.com:8443")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil || string(data) != "public_addr: vpn.example.com:8443\n" {
		t.Errorf("config: %q %v", data, err)
	}
	if fi, _ := os.Stat(cfgPath); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 {
		t.Errorf("config mode %o", fi.Mode().Perm())
	}
	s := env.mgr.installed[0]
	if s.Name != serviceServer || !s.Reload || strings.Join(s.Args, " ") != "server --config "+cfgPath {
		t.Errorf("service: %+v", s)
	}
	if len(s.ReadWritePaths) == 0 || s.ReadWritePaths[0] != "/var/lib/thawr" {
		t.Errorf("rw paths: %v", s.ReadWritePaths)
	}
	// systemd refuses a unit whose ReadWritePaths are missing: the data
	// directory is created before the service is registered.
	if len(env.dirs) != 1 || env.dirs[0] != "/var/lib/thawr" {
		t.Errorf("directories created: %v, want the data_dir", env.dirs)
	}
	if !strings.Contains(out, "wrote "+cfgPath) || !strings.Contains(out, "thawr-server started") {
		t.Errorf("output: %s", out)
	}
	if got := strings.Join(env.calls, ","); got != "install,start thawr-server" {
		t.Errorf("calls: %s", got)
	}
}

func TestServerInstallRefusesExistingConfig(t *testing.T) {
	env := newInstallEnv(t)
	cfgPath := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(cfgPath, []byte("public_addr: old.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := env.run(t, "server", "install", "--config", cfgPath, "--public-addr", "new.example.com")
	if code != exitConfigError || !strings.Contains(errOut, "exists") {
		t.Errorf("code %d: %s", code, errOut)
	}
	data, _ := os.ReadFile(cfgPath)
	if string(data) != "public_addr: old.example.com\n" || len(env.calls) != 0 {
		t.Errorf("config changed or manager called: %q %v", data, env.calls)
	}
	// Without a file and without --public-addr there is nothing to install.
	if _, errOut, code := env.run(t, "server", "install", "--config", filepath.Join(t.TempDir(), "none.yaml")); code != exitConfigError || !strings.Contains(errOut, "--public-addr") {
		t.Errorf("code %d: %s", code, errOut)
	}
	// An existing file is used as is.
	if _, errOut, code := env.run(t, "server", "install", "--config", cfgPath, "--no-start"); code != 0 {
		t.Errorf("code %d: %s", code, errOut)
	}
}

func TestUninstallPurgeNeedsYes(t *testing.T) {
	env := newInstallEnv(t)
	stateDir := t.TempDir()
	if err := client.SaveState(stateDir, enrolledState()); err != nil {
		t.Fatal(err)
	}
	env.mgr.state = svc.Running
	out, errOut, code := env.run(t, "client", "uninstall", "--state-dir", stateDir, "--purge")
	if code != exitConfigError || !strings.Contains(errOut, "--yes") || !strings.Contains(errOut, filepath.Join(stateDir, client.StateFile)) {
		t.Errorf("code %d: %s %s", code, out, errOut)
	}
	if len(env.calls) != 0 {
		t.Errorf("service touched before --yes: %v", env.calls)
	}
	if _, err := client.LoadState(stateDir); err != nil {
		t.Error("state deleted without --yes")
	}
	out, errOut, code = env.run(t, "client", "uninstall", "--state-dir", stateDir, "--purge", "--yes")
	if code != 0 || !strings.Contains(out, "deleted") || strings.Join(env.calls, ",") != "stop thawr-client,uninstall thawr-client" {
		t.Errorf("code %d: %s %s", code, out, errOut)
	}
	if _, err := client.LoadState(stateDir); !errors.Is(err, client.ErrNotEnrolled) {
		t.Errorf("state kept: %v", err)
	}
	// Without --purge the enrollment stays.
	if err := client.SaveState(stateDir, enrolledState()); err != nil {
		t.Fatal(err)
	}
	if out, _, code := env.run(t, "client", "uninstall", "--state-dir", stateDir); code != 0 || !strings.Contains(out, "data kept") {
		t.Errorf("code %d: %s", code, out)
	}
	if _, err := client.LoadState(stateDir); err != nil {
		t.Error("state removed without --purge")
	}
}

func TestServerUninstallPurgeDeletesDataDir(t *testing.T) {
	env := newInstallEnv(t)
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(cfgPath, []byte("public_addr: vpn.example.com\ndata_dir: "+dataDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.mgr.state = svc.Stopped
	if _, errOut, code := env.run(t, "server", "uninstall", "--config", cfgPath, "--purge", "--yes"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if _, err := os.Stat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Error("data_dir kept")
	}
	if got := strings.Join(env.calls, ","); got != "uninstall thawr-server" {
		t.Errorf("calls: %s", got)
	}
}
