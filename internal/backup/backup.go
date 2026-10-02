// Package backup is the server backup archive format (spec 014): a
// gzip-compressed tar whose first entry, manifest.json, lists every
// other entry with its size and SHA-256. Write produces an archive from
// files on disk; Extract verifies one while writing it into a directory
// and refuses anything the manifest does not describe exactly.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Format is the archive format version this package writes and reads.
const Format = 1

// ManifestName is the archive's first entry.
const ManifestName = "manifest.json"

// maxManifestSize bounds the manifest read before anything is trusted.
const maxManifestSize = 1 << 20

// maxTarPadding is one tar record (20 blocks of 512 bytes), the most
// padding a tar writer adds after the end marker.
const maxTarPadding = 20 * 512

// ErrInvalid marks an archive that is malformed, tampered with, or does
// not match its manifest.
var ErrInvalid = errors.New("invalid backup archive")

// Manifest describes an archive.
type Manifest struct {
	Format               int       `json:"format"`
	ThawrVersion         string    `json:"thawr_version"`
	SchemaVersion        int       `json:"schema_version"`
	Created              time.Time `json:"created"`
	ServerKeyFingerprint string    `json:"server_key_fingerprint"`
	TLSMode              string    `json:"tls_mode"`
	Files                []File    `json:"files"`
}

// File is one archive entry other than the manifest.
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Source maps an archive path (slash-separated, relative) to a file on
// disk.
type Source struct {
	Path string
	From string
}

// Write fills m.Files from srcs (size and SHA-256 of each file as read
// now) and writes the archive to w: the manifest first, then the files
// in the order given, every entry with mode 0600.
func Write(w io.Writer, m Manifest, srcs []Source) (Manifest, error) {
	m.Format = Format
	m.Files = make([]File, 0, len(srcs))
	seen := make(map[string]bool, len(srcs))
	for _, s := range srcs {
		if err := checkPath(s.Path); err != nil {
			return m, err
		}
		if seen[s.Path] {
			return m, fmt.Errorf("backup: %s listed twice", s.Path)
		}
		seen[s.Path] = true
		size, sum, err := hashFile(s.From)
		if err != nil {
			return m, err
		}
		m.Files = append(m.Files, File{Path: s.Path, Size: size, SHA256: sum})
	}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, fmt.Errorf("backup: manifest: %w", err)
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	if err := writeEntry(tw, ManifestName, int64(len(mj)), m.Created, strings.NewReader(string(mj))); err != nil {
		return m, err
	}
	for i, s := range srcs {
		if err := copyFile(tw, s, m.Files[i], m.Created); err != nil {
			return m, err
		}
	}
	if err := tw.Close(); err != nil {
		return m, fmt.Errorf("backup: close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return m, fmt.Errorf("backup: close gzip: %w", err)
	}
	return m, nil
}

// copyFile writes one source, refusing a file that changed size since
// it was hashed (the archive must match its manifest).
func copyFile(tw *tar.Writer, s Source, f File, mod time.Time) error {
	in, err := os.Open(s.From)
	if err != nil {
		return fmt.Errorf("backup: open %s: %w", s.From, err)
	}
	defer func() { _ = in.Close() }()
	h := sha256.New()
	if err := writeEntry(tw, s.Path, f.Size, mod, io.TeeReader(io.LimitReader(in, f.Size), h)); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("backup: %s changed while it was archived", s.From)
	}
	return nil
}

func writeEntry(tw *tar.Writer, name string, size int64, mod time.Time, r io.Reader) error {
	hdr := &tar.Header{Typeflag: tar.TypeReg, Name: name, Size: size, Mode: 0o600, ModTime: mod.UTC(), Format: tar.FormatPAX}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("backup: header %s: %w", name, err)
	}
	n, err := io.Copy(tw, r)
	if err != nil {
		return fmt.Errorf("backup: write %s: %w", name, err)
	}
	if n != size {
		return fmt.Errorf("backup: %s changed while it was archived", name)
	}
	return nil
}

func hashFile(p string) (int64, string, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, "", fmt.Errorf("backup: open %s: %w", p, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", fmt.Errorf("backup: read %s: %w", p, err)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// checkPath accepts a clean, relative, slash-separated path without
// "..", the only shape Extract writes.
func checkPath(p string) error {
	if p == "" || p == ManifestName || strings.Contains(p, "\\") || path.IsAbs(p) || path.Clean(p) != p || p == "." ||
		strings.HasPrefix(p, "../") || p == ".." || filepath.VolumeName(p) != "" {
		return fmt.Errorf("%w: path %q", ErrInvalid, p)
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return fmt.Errorf("%w: path %q", ErrInvalid, p)
		}
	}
	return nil
}

// Extract reads an archive from r into dir (created 0700 if needed;
// files 0600, directories 0700), verifying each entry against the
// manifest as it is written. It fails with an error wrapping ErrInvalid
// when the manifest is missing or not the first entry, the format is
// unknown, an entry is not a regular file, a path is unsafe, a file is
// missing, extra, duplicated, or its size or SHA-256 differ. dir may be
// left partly written on error; the caller extracts into a fresh
// temporary directory.
func Extract(r io.Reader, dir string) (Manifest, error) {
	var m Manifest
	gz, err := gzip.NewReader(r)
	if err != nil {
		return m, fmt.Errorf("%w: not gzip: %w", ErrInvalid, err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)

	hdr, err := tr.Next()
	if err != nil {
		return m, fmt.Errorf("%w: empty archive: %w", ErrInvalid, err)
	}
	if hdr.Name != ManifestName || hdr.Typeflag != tar.TypeReg || hdr.Size > maxManifestSize {
		return m, fmt.Errorf("%w: first entry must be %s", ErrInvalid, ManifestName)
	}
	if err := json.NewDecoder(io.LimitReader(tr, maxManifestSize)).Decode(&m); err != nil {
		return m, fmt.Errorf("%w: manifest: %w", ErrInvalid, err)
	}
	if m.Format != Format {
		return m, fmt.Errorf("%w: format %d, this binary reads %d", ErrInvalid, m.Format, Format)
	}
	want := make(map[string]File, len(m.Files))
	for _, f := range m.Files {
		if err := checkPath(f.Path); err != nil {
			return m, err
		}
		if _, dup := want[f.Path]; dup || f.Size < 0 {
			return m, fmt.Errorf("%w: manifest entry %q", ErrInvalid, f.Path)
		}
		want[f.Path] = f
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return m, fmt.Errorf("backup: create %s: %w", dir, err)
	}
	got := make(map[string]bool, len(want))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		f, ok := want[hdr.Name]
		if !ok || got[hdr.Name] {
			return m, fmt.Errorf("%w: unexpected entry %q", ErrInvalid, hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size != f.Size {
			return m, fmt.Errorf("%w: entry %q does not match the manifest", ErrInvalid, hdr.Name)
		}
		if err := extractFile(tr, dir, f); err != nil {
			return m, err
		}
		got[hdr.Name] = true
	}
	for p := range want {
		if !got[p] {
			return m, fmt.Errorf("%w: %s missing", ErrInvalid, p)
		}
	}
	// The tar end marker comes before the gzip trailer; only reading the
	// stream to its end checks the trailer's CRC-32 and length, so a cut
	// or extended file is refused. At most one tar record of padding
	// may follow the end marker.
	n, err := io.Copy(io.Discard, io.LimitReader(gz, maxTarPadding+1))
	if err != nil {
		return m, fmt.Errorf("%w: gzip: %w", ErrInvalid, err)
	}
	if n > maxTarPadding {
		return m, fmt.Errorf("%w: data after the end of the archive", ErrInvalid)
	}
	return m, nil
}

func extractFile(r io.Reader, dir string, f File) error {
	dst := filepath.Join(dir, filepath.FromSlash(f.Path))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("backup: create %s: %w", filepath.Dir(dst), err)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("backup: create %s: %w", dst, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, f.Size+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("backup: write %s: %w", dst, err)
	}
	if n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("%w: %s does not match its checksum", ErrInvalid, f.Path)
	}
	return nil
}
