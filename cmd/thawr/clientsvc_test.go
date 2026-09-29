package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sira-labs/thawr/internal/svc"
)

func TestClientStartStop(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		state     svc.State
		wantCode  int
		wantCalls string
		wantOut   string
	}{
		{"start stopped", []string{"client", "start"}, svc.Stopped, 0, "start " + serviceClient, "started"},
		{"start running", []string{"client", "start"}, svc.Running, 0, "", "already running"},
		{"start absent", []string{"client", "start"}, svc.Absent, exitConfigError, "", "not installed"},
		{"stop running", []string{"client", "stop"}, svc.Running, 0, "stop " + serviceClient, "client start"},
		{"stop stopped", []string{"client", "stop"}, svc.Stopped, 0, "", "not running"},
		{"stop absent", []string{"client", "stop"}, svc.Absent, exitConfigError, "", "client down"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t)
			env.mgr.states = map[string]svc.State{serviceClient: tc.state}
			args := tc.args
			if tc.args[1] == "start" {
				args = append(args, "--socket", filepath.Join(t.TempDir(), "none.sock"))
			}
			out, errOut, code := env.run(t, args...)
			if code != tc.wantCode || !strings.Contains(out+errOut, tc.wantOut) {
				t.Errorf("code %d (want %d), output %q (want %q)", code, tc.wantCode, out+errOut, tc.wantOut)
			}
			if got := strings.Join(env.calls, ","); got != tc.wantCalls {
				t.Errorf("calls = %q, want %q", got, tc.wantCalls)
			}
		})
	}
	env := newInstallEnv(t)
	env.deps.isRoot = func() bool { return false }
	for _, verb := range []string{"start", "stop"} {
		if _, errOut, code := env.run(t, "client", verb); code != exitConfigError || !strings.Contains(errOut, "needs root") {
			t.Errorf("client %s without root: code %d, %s", verb, code, errOut)
		}
	}
}
