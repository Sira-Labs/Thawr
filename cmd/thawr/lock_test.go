package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thedatadudech/thawr/internal/client"
)

// lockDaemon fakes the daemon's lock endpoints: a signer that knows
// peers "nas" and "hub", refuses "box", and reports its status.
func lockDaemon(t *testing.T, st client.Status) string {
	t.Helper()
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, res client.LockResult) { _ = json.NewEncoder(w).Encode(res) }
	fail := func(w http.ResponseWriter, code int, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(st) })
	mux.HandleFunc("POST /lock/init", func(w http.ResponseWriter, _ *http.Request) {
		ok(w, client.LockResult{Generation: 1, Signer: "aa11bb22", PublicKey: "LOCKPUB=", Signed: []client.LockSigned{{Name: "hub", Fingerprint: "0a0a0a0a"}, {Name: "laptop", Fingerprint: "0b0b0b0b"}}})
	})
	mux.HandleFunc("POST /lock/sign/{name}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("name") {
		case "nas":
			ok(w, client.LockResult{Generation: 1, Signer: "aa11bb22", Signed: []client.LockSigned{{Name: "nas", Fingerprint: "0c0c0c0c"}}})
		case "all":
			ok(w, client.LockResult{Generation: 1, Signer: "aa11bb22", Signed: []client.LockSigned{}})
		case "box":
			fail(w, http.StatusNotFound, "client: unknown peer: box")
		default:
			fail(w, http.StatusForbidden, "client: this device is not a signer of the network lock")
		}
	})
	mux.HandleFunc("POST /lock/key", func(w http.ResponseWriter, _ *http.Request) {
		ok(w, client.LockResult{Signer: "cc33dd44", PublicKey: "NEWPUB="})
	})
	mux.HandleFunc("POST /lock/add-signer/{name}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("name") != "nas" {
			fail(w, http.StatusConflict, "client: box has not reported a lock key; run `thawr client lock key` there first")
			return
		}
		if r.URL.Query().Get("key") != "cc33dd44" {
			fail(w, http.StatusConflict, "client: lock key mismatch")
			return
		}
		ok(w, client.LockResult{Generation: 2, Signer: "aa11bb22", Signed: []client.LockSigned{{Name: "nas", Fingerprint: "cc33dd44"}}})
	})
	mux.HandleFunc("POST /lock/disable", func(w http.ResponseWriter, _ *http.Request) {
		ok(w, client.LockResult{Generation: 3, Signer: "aa11bb22"})
	})
	return fakeDaemonSocket(t, mux)
}

func lockedStatus() client.Status {
	st := statusFixture()
	st.Lock = client.LockStatus{Enabled: true, Signer: true, HasKey: true, Generation: 2, SelfSigned: true,
		Signers: []client.LockSignerStatus{{PeerID: "p1", Name: "alice-laptop", Key: "LOCKPUB=", Fingerprint: "aa11bb22"}, {PeerID: "p9", Key: "OTHER=", Fingerprint: "ee55ff66"}}}
	st.Held = []client.HeldStatus{{Name: "build-box", IPv4: "100.64.0.9", Kind: "agent", OfferedKey: "BLD=", Since: st.RetrievedAt, Reason: client.HeldUnsigned}}
	st.Peers[1].Path, st.Peers[1].PathEndpoint, st.Peers[1].LastHandshakeAt = client.PathUnsigned, "", nil
	return st
}

func TestClientLockCommands(t *testing.T) {
	sock := lockDaemon(t, lockedStatus())
	cases := []struct {
		name string
		args []string
		code int
		want []string
	}{
		{"init", []string{"lock", "init"}, 0, []string{"network lock enabled (generation 1); this device signs with aa11bb22", "signed hub (0a0a0a0a)", "signed laptop (0b0b0b0b)", "compare each fingerprint"}},
		{"sign", []string{"lock", "sign", "nas"}, 0, []string{"signed nas (0c0c0c0c)"}},
		{"sign all", []string{"lock", "sign", "--all"}, 0, []string{"nothing to sign"}},
		{"key", []string{"lock", "key"}, 0, []string{"lock public key NEWPUB= (fingerprint cc33dd44)", "thawr client lock add-signer <this peer's name> cc33dd44"}},
		{"add-signer", []string{"lock", "add-signer", "nas", "cc33dd44"}, 0, []string{"added nas as signer (cc33dd44); record generation 2"}},
		{"disable", []string{"lock", "disable"}, 0, []string{"network lock disabled (generation 3)"}},
		{"status", []string{"lock", "status"}, 0, []string{"lock: on (generation 2) · this device is a signer", "signer alice-laptop (aa11bb22)", "signer p9 (ee55ff66)", "unsigned, held: build-box (sign with: thawr client lock sign build-box)"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"client"}, tc.args...)
			out, code, err := runCLI(t, append(args, "--socket", sock)...)
			if code != tc.code {
				t.Fatalf("code %d err=%v out=%q", code, err, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
		})
	}
	if out, code, err := runCLI(t, "client", "lock", "sign", "box", "--socket", sock); code != exitConfigError || !strings.Contains(err.Error(), "unknown peer: box") || out != "" {
		t.Errorf("unknown peer: %q code=%d err=%v", out, code, err)
	}
	if _, code, err := runCLI(t, "client", "lock", "sign", "other", "--socket", sock); code != exitConfigError || !strings.Contains(err.Error(), "not a signer") {
		t.Errorf("not a signer: code=%d err=%v", code, err)
	}
	if _, code, err := runCLI(t, "client", "lock", "add-signer", "box", "cc33dd44", "--socket", sock); code != exitConfigError || !strings.Contains(err.Error(), "has not reported a lock key") {
		t.Errorf("add-signer without key: code=%d err=%v", code, err)
	}
	if _, code, err := runCLI(t, "client", "lock", "add-signer", "nas", "ffffffff", "--socket", sock); code != exitConfigError || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("add-signer with the wrong fingerprint: code=%d err=%v", code, err)
	}
	if _, code, _ := runCLI(t, "client", "lock", "add-signer", "nas", "--socket", sock); code != exitConfigError {
		t.Errorf("add-signer without the key argument: code=%d", code)
	}
	if _, code, _ := runCLI(t, "client", "lock", "sign", "--socket", sock); code != exitConfigError {
		t.Errorf("sign without names: code=%d", code)
	}
	if _, code, _ := runCLI(t, "client", "lock", "sign", "nas", "--all", "--socket", sock); code != exitConfigError {
		t.Errorf("sign name and --all: code=%d", code)
	}
	if _, code, _ := runCLI(t, "client", "lock", "init", "--socket", filepath.Join(t.TempDir(), "missing.sock")); code != exitNotRunning {
		t.Errorf("not running: code=%d", code)
	}
	if out, _, _ := runCLI(t, "client", "--help"); !strings.Contains(out, "lock") {
		t.Error("client help does not list lock")
	}
}

// TestClientLockStatusOff: the off state names the command that
// enables the lock and shows a refused record.
func TestClientLockStatusOff(t *testing.T) {
	st := statusFixture()
	st.Lock.Rejected = "offered record (generation 9) refused: lock: not signed by a current signer"
	sock := lockDaemon(t, st)
	out, code, _ := runCLI(t, "client", "lock", "status", "--socket", sock)
	if code != 0 || !strings.HasPrefix(out, "lock: off\n") || !strings.Contains(out, "warning: offered record (generation 9) refused") {
		t.Errorf("lock status off: %q code=%d", out, code)
	}
	st.Lock = client.LockStatus{Enabled: true, Generation: 1, HasKey: true, Signers: []client.LockSignerStatus{{PeerID: "p9", Fingerprint: "ee55ff66"}}}
	sock = lockDaemon(t, st)
	out, _, _ = runCLI(t, "client", "lock", "status", "--socket", sock)
	for _, w := range []string{"this device has a lock key but is not a signer yet", "this device is unsigned; other devices hold it until a signer runs: thawr client lock sign alice-laptop"} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

// TestStatusRenderLock: the header shows the lock state, an unsigned
// peer is listed with the sign hint and its row reads "unsigned".
func TestStatusRenderLock(t *testing.T) {
	st := lockedStatus()
	st.Lock.Signer = false
	sock := fakeDaemon(t, st)
	out, code, _ := runCLI(t, "client", "status", "--socket", sock)
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	for _, want := range []string{" · lock: on · 1 unsigned: thawr client lock sign build-box\n", "build-box     100.64.0.9    agent    -       unsigned"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	st.Lock.Signer = true
	if out, _, _ := runCLI(t, "client", "status", "--socket", fakeDaemon(t, st)); !strings.Contains(out, " · lock: on (signer) · ") {
		t.Errorf("signer header: %s", out)
	}
	st.Lock.Signer, st.Lock.SelfSigned = false, false
	if out, _, _ := runCLI(t, "client", "status", "--socket", fakeDaemon(t, st)); !strings.Contains(out, " · lock: on, this device unsigned · ") {
		t.Errorf("self-unsigned header: %s", out)
	}
}

// fakeLockAPI serves GET /api/v1/lock on an admin socket.
func fakeLockAPI(t *testing.T, enabled bool) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/lock", func(w http.ResponseWriter, _ *http.Request) {
		v := map[string]any{"enabled": enabled, "generation": 2, "signers": []map[string]string{}, "unsigned": []string{}}
		if enabled {
			v["signers"] = []map[string]string{{"peer": "alice-box", "key": "LOCKPUB=", "fingerprint": "aa11bb22"}}
			v["unsigned"] = []string{"hub", "markus-box"}
		}
		_ = json.NewEncoder(w).Encode(v)
	})
	return fakeDaemonSocket(t, mux)
}

func TestAdminLock(t *testing.T) {
	out, code, err := runCLI(t, "admin", "lock", "--socket", fakeLockAPI(t, true))
	if code != 0 {
		t.Fatalf("exit %d: %v", code, err)
	}
	for _, want := range []string{"lock: on (generation 2)", "signer alice-box (aa11bb22)", "unsigned: hub markus-box"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if out, _, _ := runCLI(t, "admin", "lock", "--socket", fakeLockAPI(t, false)); !strings.Contains(out, "lock: off (disabled at generation 2)") {
		t.Errorf("off: %s", out)
	}
	out, _, _ = runCLI(t, "admin", "lock", "--json", "--socket", fakeLockAPI(t, true))
	var l lockJSON
	if err := json.Unmarshal([]byte(out), &l); err != nil || !l.Enabled || len(l.Signers) != 1 || l.Signers[0].Peer != "alice-box" {
		t.Errorf("--json: %v %s", err, out)
	}
	if out, _, _ := runCLI(t, "admin", "--help"); !strings.Contains(out, "lock") {
		t.Error("admin help does not list lock")
	}
}
