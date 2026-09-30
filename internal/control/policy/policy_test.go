package policy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadExample(t *testing.T) {
	p, err := Load(filepath.Join("..", "..", "..", "config", "policy.example.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Version != 1 || len(p.ACLs) != 3 || len(p.Groups) != 2 {
		t.Errorf("unexpected policy: %+v", p)
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "none.yaml"))
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"bad yaml":      "version: [\n",
		"wrong version": "version: 2\n",
		"no version":    "acls: []\n",
		"deny action":   "version: 1\nacls:\n  - action: deny\n    src: ['*']\n    dst: ['*:*']\n",
		"bad selector":  "version: 1\nacls:\n  - action: accept\n    src: ['Bad Name']\n    dst: ['*:*']\n",
		"unknown key":   "version: 1\nrules: []\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Errorf("expected error for %q", doc)
			}
		})
	}
}

func TestLoadUnreadable(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("root and Windows can read a mode-000 file")
	}
	path := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want a read error", err)
	}
}

func TestPeerReferences(t *testing.T) {
	p, err := Parse([]byte(`version: 1
acls:
  - action: accept
    src: ["peer:ci", "*"]
    dst: ["peer:db:5432", "self:*"]
  - action: accept
    src: ["peer:db"]
    dst: ["tag:prod:22"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := p.PeerReferences()
	want := map[string][]string{
		"ci": {"acls[0].src[0]"},
		"db": {"acls[0].dst[0]", "acls[1].src[0]"},
	}
	if len(got) != len(want) {
		t.Fatalf("PeerReferences = %v, want %v", got, want)
	}
	for name, where := range want {
		if strings.Join(got[name], ",") != strings.Join(where, ",") {
			t.Errorf("PeerReferences[%q] = %v, want %v", name, got[name], where)
		}
	}
	if refs := Empty().PeerReferences(); len(refs) != 0 {
		t.Errorf("Empty().PeerReferences() = %v, want none", refs)
	}
}
