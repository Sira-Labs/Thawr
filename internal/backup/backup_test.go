package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWriteExtractRoundTrip(t *testing.T) {
	src := t.TempDir()
	srcs := []Source{
		{Path: "thawr.db", From: writeFile(t, src, "db", "database bytes")},
		{Path: "server.key", From: writeFile(t, src, "key", "secret\n")},
		{Path: "tls/cert.pem", From: writeFile(t, src, "cert", "cert")},
	}
	var buf bytes.Buffer
	in := Manifest{ThawrVersion: "v0.2.0", SchemaVersion: 6, Created: time.Unix(1700000000, 0).UTC(), TLSMode: "self-signed"}
	written, err := Write(&buf, in, srcs)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(written.Files) != 3 || written.Format != Format {
		t.Fatalf("manifest: %+v", written)
	}

	dst := filepath.Join(t.TempDir(), "out")
	got, err := Extract(&buf, dst)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got.SchemaVersion != 6 || got.ThawrVersion != "v0.2.0" || len(got.Files) != 3 {
		t.Errorf("manifest after extract: %+v", got)
	}
	b, err := os.ReadFile(filepath.Join(dst, "tls", "cert.pem"))
	if err != nil || string(b) != "cert" {
		t.Errorf("tls/cert.pem = %q, %v", b, err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dst, "server.key"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("server.key mode %v, want 0600", fi.Mode().Perm())
		}
	}
}

// The tar stream ends before the gzip trailer (CRC-32 and length), so a
// cut or extended file must still be refused.
func TestExtractChecksGzipTrailer(t *testing.T) {
	src := t.TempDir()
	var buf bytes.Buffer
	if _, err := Write(&buf, Manifest{}, []Source{{Path: "a", From: writeFile(t, src, "a", "hello")}}); err != nil {
		t.Fatal(err)
	}
	full := buf.Bytes()
	tests := map[string][]byte{
		"last byte cut":    full[:len(full)-1],
		"trailer cut":      full[:len(full)-8],
		"trailing garbage": append(append([]byte{}, full...), "junk"...),
		"padding too long": craftPadded(t, maxTarPadding+1),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Extract(bytes.NewReader(data), filepath.Join(t.TempDir(), "out")); !errors.Is(err, ErrInvalid) {
				t.Errorf("Extract = %v, want ErrInvalid", err)
			}
		})
	}
	for name, data := range map[string][]byte{"whole archive": full, "one record of padding": craftPadded(t, maxTarPadding)} {
		if _, err := Extract(bytes.NewReader(data), filepath.Join(t.TempDir(), "out")); err != nil {
			t.Errorf("Extract of %s: %v", name, err)
		}
	}
}

// craftPadded is an empty valid archive whose tar stream carries n zero
// bytes after its end marker, inside the gzip stream.
func craftPadded(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	m, err := json.Marshal(Manifest{Format: Format})
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(m)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(m); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := gz.Write(make([]byte, n)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestWriteRefusesBadPaths(t *testing.T) {
	f := writeFile(t, t.TempDir(), "x", "x")
	for _, p := range []string{"", "../x", "/abs", "a/../../b", "manifest.json", `a\b`, "a//b"} {
		if _, err := Write(&bytes.Buffer{}, Manifest{}, []Source{{Path: p, From: f}}); err == nil {
			t.Errorf("Write accepted path %q", p)
		}
	}
	if _, err := Write(&bytes.Buffer{}, Manifest{}, []Source{{Path: "a", From: f}, {Path: "a", From: f}}); err == nil {
		t.Error("Write accepted a duplicate path")
	}
}

type entry struct {
	name    string
	body    string
	typ     byte
	hdrSize int64 // -1: len(body)
}

// craft builds an archive by hand so tests can produce what Write never
// would.
func craft(t *testing.T, manifest any, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if manifest != nil {
		mj, _ := json.Marshal(manifest)
		entries = append([]entry{{name: ManifestName, body: string(mj), hdrSize: -1}}, entries...)
	}
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		size := e.hdrSize
		if size < 0 {
			size = int64(len(e.body))
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Size: size, Mode: 0o600}
		if typ == tar.TypeSymlink {
			hdr.Linkname, hdr.Size = "/etc/passwd", 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestExtractRefuses(t *testing.T) {
	good := Manifest{Format: Format, Files: []File{{Path: "a", Size: 5, SHA256: sum("hello")}}}
	tests := []struct {
		name     string
		manifest any
		entries  []entry
	}{
		{"tampered byte", good, []entry{{name: "a", body: "hellp", hdrSize: -1}}},
		{"missing file", good, nil},
		{"extra file", good, []entry{{name: "a", body: "hello", hdrSize: -1}, {name: "b", body: "x", hdrSize: -1}}},
		{"duplicate entry", good, []entry{{name: "a", body: "hello", hdrSize: -1}, {name: "a", body: "hello", hdrSize: -1}}},
		{"symlink", good, []entry{{name: "a", typ: tar.TypeSymlink}}},
		{"size differs", good, []entry{{name: "a", body: "hello!", hdrSize: -1}}},
		{"no manifest", nil, []entry{{name: "a", body: "hello", hdrSize: -1}}},
		{"unknown format", Manifest{Format: 99}, nil},
		{"dotdot in manifest", Manifest{Format: Format, Files: []File{{Path: "../evil", Size: 1, SHA256: sum("x")}}}, []entry{{name: "../evil", body: "x", hdrSize: -1}}},
		{"absolute in manifest", Manifest{Format: Format, Files: []File{{Path: "/etc/x", Size: 1, SHA256: sum("x")}}}, []entry{{name: "/etc/x", body: "x", hdrSize: -1}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "out")
			_, err := Extract(bytes.NewReader(craft(t, tc.manifest, tc.entries)), dst)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Extract: got %v, want ErrInvalid", err)
			}
		})
	}
	if _, err := Extract(bytes.NewReader([]byte("not a gzip stream")), t.TempDir()); !errors.Is(err, ErrInvalid) {
		t.Errorf("garbage: got %v, want ErrInvalid", err)
	}
}
