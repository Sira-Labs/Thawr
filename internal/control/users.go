package control

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/sira-labs/thawr/internal/store"
)

// argon2id parameters (threat model: 64 MiB, 3 iterations, 4 lanes).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16

	minPasswordLen = 8
	maxPasswordLen = 256

	loginWindow    = 15 * time.Minute
	loginThreshold = 10
	loginMaxDelay  = 15 * time.Minute
)

// Users creates and authenticates local accounts.
type Users struct {
	store *store.Store
	now   func() time.Time
	log   *slog.Logger
	limit *limiter
	// dummyHash keeps the cost of a failed lookup equal to a real check.
	dummyHash string
	audit     *Auditor
}

// WithAuditor records user creation and logins in the audit log.
func (u *Users) WithAuditor(a *Auditor) *Users {
	u.audit = a
	return u
}

// NewUsers builds the user service.
func NewUsers(st *store.Store, now func() time.Time, log *slog.Logger) (*Users, error) {
	dummy, err := hashPassword("thawr-dummy-password-for-constant-time")
	if err != nil {
		return nil, err
	}
	return &Users{
		store:     st,
		now:       now,
		log:       log,
		limit:     newLimiter(now, loginWindow, loginThreshold, loginMaxDelay),
		dummyHash: dummy,
	}, nil
}

// Create adds a user on behalf of by, which the audit row names. The
// password is hashed with argon2id and never stored or logged in clear.
func (u *Users) Create(ctx context.Context, by Principal, name, role, password string) (store.User, error) {
	if !validLabel(name) {
		return store.User{}, fmt.Errorf("%w: name %q must be 1-63 lowercase letters, digits or hyphens", ErrValidation, name)
	}
	if role != store.RoleAdmin && role != store.RoleMember {
		return store.User{}, fmt.Errorf("%w: role %q must be admin or member", ErrValidation, role)
	}
	if n := len(password); n < minPasswordLen || n > maxPasswordLen {
		return store.User{}, fmt.Errorf("%w: password must be %d-%d characters", ErrValidation, minPasswordLen, maxPasswordLen)
	}
	hash, err := hashPassword(password)
	if err != nil {
		return store.User{}, err
	}
	id, err := newID()
	if err != nil {
		return store.User{}, err
	}
	user := store.User{ID: id, Name: name, Role: role, PasswordHash: hash, CreatedAt: u.now()}
	err = u.store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.Users().Create(ctx, user); err != nil {
			return err
		}
		return u.audit.Record(ctx, tx, by, AuditUserCreate, user.ID, map[string]string{"name": name, "role": role})
	})
	if err != nil {
		return store.User{}, err
	}
	u.log.Info("user created", "user", name, "role", role)
	return user, nil
}

// Authenticate checks name and password. Failures are rate limited per
// user and return ErrForbidden or ErrRateLimited.
func (u *Users) Authenticate(ctx context.Context, name, password string) (store.User, error) {
	if !u.limit.allow(name) {
		u.log.Warn("login rate limited", "user", name)
		return store.User{}, ErrRateLimited
	}
	user, err := u.store.Users().GetByName(ctx, name)
	hash := u.dummyHash
	found := err == nil && !user.Disabled
	if found {
		hash = user.PasswordHash
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}
	ok, err := verifyPassword(hash, password)
	if err != nil {
		return store.User{}, err
	}
	if !ok || !found {
		u.limit.fail(name)
		u.log.Warn("login failed", "user", name)
		if err := u.audit.Record(ctx, u.store, anonymousPrincipal(name), AuditLoginFailed, name, nil); err != nil {
			u.log.Error("audit login failure", "err", err)
		}
		return store.User{}, ErrForbidden
	}
	u.limit.reset(name)
	u.log.Info("login ok", "user", name)
	if err := u.audit.Record(ctx, u.store, Principal{UserID: user.ID, Name: user.Name, Role: user.Role}, AuditLoginOK, name, nil); err != nil {
		return store.User{}, err
	}
	return user, nil
}

// List returns all users.
func (u *Users) List(ctx context.Context) ([]store.User, error) {
	return u.store.Users().List(ctx)
}

// Get returns a user by id.
func (u *Users) Get(ctx context.Context, id string) (store.User, error) {
	user, err := u.store.Users().GetByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, fmt.Errorf("user %s: %w", id, ErrNotFound)
	}
	return user, err
}

// hashPassword returns a PHC-formatted argon2id string.
func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("control: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyPassword checks password against a PHC argon2id string in
// constant time with respect to the hash contents.
func verifyPassword(phc, password string) (bool, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("control: unsupported password hash format")
	}
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false, fmt.Errorf("control: parse password hash params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("control: parse password salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("control: parse password hash: %w", err)
	}
	if len(want) != argonKeyLen {
		return false, fmt.Errorf("control: password hash has unexpected length %d", len(want))
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, argonKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
