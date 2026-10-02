package client

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// openWithoutShareDelete opens path the way a scanner might: readers and
// writers are admitted, a rename over it is not.
func openWithoutShareDelete(t *testing.T, path string) windows.Handle {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	return h
}

func TestReplaceFileWaitsForReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, StateFile)
	tmp := path + ".tmp"
	for name, data := range map[string]string{path: "old", tmp: "new"} {
		if err := os.WriteFile(name, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := openWithoutShareDelete(t, path)
	if err := os.Rename(tmp, path); err == nil {
		t.Fatal("plain rename replaced a file held open without FILE_SHARE_DELETE; the test proves nothing")
	}
	released := make(chan struct{})
	go func() {
		defer close(released)
		time.Sleep(50 * time.Millisecond)
		_ = windows.CloseHandle(h)
	}()
	err := replaceFile(tmp, path)
	<-released
	if err != nil {
		t.Fatalf("replaceFile: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "new" {
		t.Errorf("after replace: %q %v", got, err)
	}
}

func TestReplaceFileReturnsOtherErrors(t *testing.T) {
	dir := t.TempDir()
	start := time.Now()
	err := replaceFile(filepath.Join(dir, "missing.tmp"), filepath.Join(dir, StateFile))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replaceFile of a missing file: %v", err)
	}
	if time.Since(start) > replaceTimeout/2 {
		t.Errorf("a missing file was retried for %v", time.Since(start))
	}
}
