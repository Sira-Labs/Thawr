package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

// ServerKeyFile is the name of the WireGuard private key file in data_dir.
const ServerKeyFile = "server.key"

// loadOrCreateServerKey returns the hub's WireGuard private key, creating
// it on first start, and verifies it against the fingerprint recorded in
// the database so a key and a database from different servers are never
// combined.
func loadOrCreateServerKey(ctx context.Context, path string, meta *store.Meta) (key wg.Key, created bool, err error) {
	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		key, err = wg.GenerateKey()
		if err != nil {
			return wg.Key{}, false, err
		}
		if err := writeSecretFile(path, []byte(key.String()+"\n")); err != nil {
			return wg.Key{}, false, err
		}
		created = true
	case err != nil:
		return wg.Key{}, false, fmt.Errorf("server: read %s: %w", path, err)
	default:
		key, err = wg.ParseKey(strings.TrimSpace(string(data)))
		if err != nil {
			return wg.Key{}, false, fmt.Errorf("server: %s: %w", path, err)
		}
	}
	if err := checkSecretFileMode(path); err != nil {
		return wg.Key{}, false, err
	}

	fp := wg.Fingerprint(key.PublicKey())
	stored, err := meta.Get(ctx, store.MetaServerKeyFingerprint)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if err := meta.Set(ctx, store.MetaServerKeyFingerprint, fp); err != nil {
			return wg.Key{}, false, err
		}
	case err != nil:
		return wg.Key{}, false, err
	case stored != fp:
		return wg.Key{}, false, fmt.Errorf("server: %s (fingerprint %s) does not match the database (fingerprint %s); the key and the database come from different servers", path, fp, stored)
	}
	return key, created, nil
}
