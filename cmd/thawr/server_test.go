package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestServerCheckWarnsACMEWithOldClients: --check passes an acme config
// but warns while clients from before 0.2 may still connect.
func TestServerCheckWarnsACMEWithOldClients(t *testing.T) {
	for _, tc := range []struct {
		name, minVersion string
		warn             bool
	}{
		{"no minimum", "", true},
		{"old minimum", "0.1", true},
		{"0.2 minimum", "0.2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := filepath.Join(dir, "server.yaml")
			yaml := "public_addr: vpn.example.org\n" +
				"data_dir: " + filepath.Join(dir, "data") + "\n" +
				"admin_socket: " + filepath.Join(dir, "admin.sock") + "\n" +
				"policy_file: " + filepath.Join(dir, "policy.yaml") + "\n" +
				"min_client_version: '" + tc.minVersion + "'\n" +
				"tls:\n  mode: acme\n  email: ops@example.org\n"
			if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			root := newRootCmd(&out, &errOut)
			root.SetArgs([]string{"server", "--check", "--config", cfg})
			if err := root.Execute(); err != nil {
				t.Fatalf("server --check: %v\n%s", err, errOut.String())
			}
			if !strings.Contains(out.String(), "ok") {
				t.Errorf("stdout %q, want ok", out.String())
			}
			if got := strings.Contains(errOut.String(), "min_client_version"); got != tc.warn {
				t.Errorf("warning shown %v, want %v:\n%s", got, tc.warn, errOut.String())
			}
			if _, err := os.Stat(filepath.Join(dir, "data")); !os.IsNotExist(err) {
				t.Errorf("--check created data_dir: %v", err)
			}
		})
	}
}
