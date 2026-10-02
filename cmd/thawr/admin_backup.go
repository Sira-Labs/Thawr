package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/sira-labs/thawr/internal/api"
	"github.com/sira-labs/thawr/internal/fsperm"
)

func newAdminBackupCmd(flags *adminFlags) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Write a backup archive of the running server (keys, database, config)",
		Long: `Writes one archive that restores this network on a fresh host with
'thawr server restore': the database, the server's WireGuard key, the
pinned TLS certificate and key, the ACME cache, and copies of the
config and policy files. Enrolled devices reconnect to a restored server
without any step on their side.

The archive holds the server's private keys: it is written with mode
0600, and it must be stored like the server's disk (an encrypted volume,
or encrypted with your backup tool). --out - writes it to standard
output.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resp, err := newAdminClient(flags.socket).stream(cmd.Context(), "/api/v1/backup")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			want := resp.Header.Get(api.BackupSHA256Header)
			if out == "-" {
				n, sum, err := copyHashed(cmd.OutOrStdout(), resp.Body)
				if err != nil {
					return err
				}
				return checkBackup(resp, n, sum, want)
			}
			dst := out
			if dst == "" {
				dst = backupName(resp)
			}
			n, sum, err := writeBackupFile(dst, resp, want)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "backup written to %s (%d bytes, sha256 %s)\nit holds the server's private keys: store it like the server's disk\n", dst, n, sum)
			return err
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "archive path (default: the server's thawr-backup-<time>.tar.gz in the current directory; - for stdout)")
	return cmd
}

// backupName is the file name the server suggested, reduced to a base
// name so a header can never point outside the current directory.
func backupName(resp *http.Response) string {
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err == nil {
		if name := filepath.Base(params["filename"]); name != "." && name != string(filepath.Separator) && name != "" {
			return name
		}
	}
	return "thawr-backup.tar.gz"
}

// writeBackupFile streams the archive into a 0600 temporary file next to
// dst, verifies size and checksum, then renames it into place, so dst is
// either the complete archive or untouched.
func writeBackupFile(dst string, resp *http.Response, want string) (int64, string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".thawr-backup-*")
	if err != nil {
		return 0, "", fmt.Errorf("create %s: %w", dst, err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := fsperm.RestrictToAdmins(tmp.Name()); err != nil {
		return 0, "", err
	}
	n, sum, err := copyHashed(tmp, resp.Body)
	if err != nil {
		return 0, "", err
	}
	if err := checkBackup(resp, n, sum, want); err != nil {
		return 0, "", err
	}
	if err := tmp.Sync(); err != nil {
		return 0, "", fmt.Errorf("write %s: %w", dst, err)
	}
	if err := tmp.Close(); err != nil {
		return 0, "", fmt.Errorf("write %s: %w", dst, err)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return 0, "", fmt.Errorf("write %s: %w", dst, err)
	}
	keep = true
	return n, sum, nil
}

func copyHashed(w io.Writer, r io.Reader) (int64, string, error) {
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), r)
	if err != nil {
		return n, "", fmt.Errorf("receive backup: %w", err)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// checkBackup compares what arrived with what the server announced, so a
// connection cut short never leaves a truncated archive behind.
func checkBackup(resp *http.Response, n int64, sum, want string) error {
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size != n {
			return fmt.Errorf("backup incomplete: received %d of %d bytes", n, size)
		}
	}
	if want != "" && want != sum {
		return fmt.Errorf("backup corrupted in transfer: sha256 %s, server sent %s", sum, want)
	}
	return nil
}
