package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

// Enrollment rate limit per remote IP.
const (
	enrollWindow = time.Minute
	enrollMax    = 10
)

// EnrollRequest is what a new client sends.
type EnrollRequest struct {
	Token         string
	PublicKey     string // base64 WireGuard public key
	Hostname      string
	OS            string
	Arch          string
	ClientVersion string
	Name          string // optional requested peer name
	RemoteIP      string
}

// EnrollResult is the newly registered peer and its node secret, which
// is returned once and stored only as a hash.
type EnrollResult struct {
	Peer       store.Peer
	NodeSecret string
	Generation int64
}

// Enroller turns a valid token into a registered agent peer.
type Enroller struct {
	store      *store.Store
	now        func() time.Time
	log        *slog.Logger
	overlay    netip.Prefix
	minVersion string
	limit      *rateLimit
	notify     Notifier
	audit      *Auditor
}

// WithAuditor records each enrollment in the audit log.
func (e *Enroller) WithAuditor(a *Auditor) *Enroller {
	e.audit = a
	return e
}

// WithNotifier sets the notifier told after each enrollment.
func (e *Enroller) WithNotifier(n Notifier) *Enroller {
	e.notify = n
	return e
}

// NewEnroller builds the enrollment service. minVersion is MAJOR.MINOR
// or empty for no gate.
func NewEnroller(st *store.Store, now func() time.Time, log *slog.Logger, overlay netip.Prefix, minVersion string) *Enroller {
	return &Enroller{
		store:      st,
		now:        now,
		log:        log,
		overlay:    overlay.Masked(),
		minVersion: minVersion,
		limit:      newRateLimit(now, enrollWindow, enrollMax),
	}
}

// Enroll validates the request, consumes the token and creates the peer
// in one transaction. Any token problem yields ErrInvalidToken with the
// same message; the reason is only logged.
func (e *Enroller) Enroll(ctx context.Context, req EnrollRequest) (EnrollResult, error) {
	if req.RemoteIP != "" && !e.limit.allow(req.RemoteIP) {
		e.log.Warn("enroll rate limited", "remote", req.RemoteIP)
		return EnrollResult{}, ErrRateLimited
	}
	if err := checkVersion(req.ClientVersion, e.minVersion); err != nil {
		return EnrollResult{}, err
	}
	pub, err := parsePublicKey(req.PublicKey)
	if err != nil {
		return EnrollResult{}, err
	}
	if len(req.Hostname) > 63 {
		return EnrollResult{}, fmt.Errorf("%w: hostname longer than 63 characters", ErrValidation)
	}
	if req.Name != "" && !validLabel(req.Name) {
		return EnrollResult{}, fmt.Errorf("%w: name %q must be a DNS label", ErrValidation, req.Name)
	}
	if !strings.HasPrefix(req.Token, TokenPrefix) || len(req.Token) != len(TokenPrefix)+43 {
		e.log.Warn("enroll rejected: malformed token", "remote", req.RemoteIP)
		return EnrollResult{}, ErrInvalidToken
	}

	nodeSecret, err := newSecret()
	if err != nil {
		return EnrollResult{}, err
	}
	peerID, err := newID()
	if err != nil {
		return EnrollResult{}, err
	}
	now := e.now()
	var result EnrollResult
	err = e.store.InTx(ctx, func(tx *store.Store) error {
		tok, err := tx.Tokens().GetByHash(ctx, hashSecret(req.Token))
		if errors.Is(err, store.ErrNotFound) {
			e.log.Warn("enroll rejected: unknown token", "remote", req.RemoteIP)
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		switch {
		case tok.UsedAt != nil:
			e.log.Warn("enroll rejected: token already used", "token", tok.ID, "remote", req.RemoteIP)
			return ErrInvalidToken
		case !tok.ExpiresAt.After(now):
			e.log.Warn("enroll rejected: token expired", "token", tok.ID, "remote", req.RemoteIP)
			return ErrInvalidToken
		}

		allocated, err := tx.Peers().AllocatedIPv4s(ctx)
		if err != nil {
			return err
		}
		addrs := make([]netip.Addr, 0, len(allocated))
		for _, a := range allocated {
			if ip, err := netip.ParseAddr(a); err == nil {
				addrs = append(addrs, ip)
			}
		}
		ip, err := NextAddress(e.overlay, addrs)
		if err != nil {
			return err
		}

		base := req.Name
		if base == "" {
			base = tok.PeerName
		}
		if base == "" {
			base = SanitizeName(req.Hostname)
		}
		name, err := uniqueName(ctx, tx.Peers(), base)
		if err != nil {
			return err
		}

		peer := store.Peer{
			ID:             peerID,
			Name:           name,
			Kind:           tok.Kind,
			Mode:           store.ModeAgent,
			OwnerID:        tok.OwnerID,
			Tags:           tok.Tags,
			PublicKey:      pub.String(),
			IPv4:           ip.String(),
			NodeSecretHash: hashSecret(nodeSecret),
			CreatedAt:      now,
			ClientVersion:  req.ClientVersion,
			OS:             platform(req.OS, req.Arch),
		}
		if err := tx.Peers().Create(ctx, peer); err != nil {
			return err
		}
		if err := tx.Tokens().MarkUsed(ctx, tok.ID, peer.ID, now); err != nil {
			if errors.Is(err, store.ErrConflict) {
				e.log.Warn("enroll rejected: token raced", "token", tok.ID, "remote", req.RemoteIP)
				return ErrInvalidToken
			}
			return err
		}
		gen, err := tx.Meta().IncrementGeneration(ctx)
		if err != nil {
			return err
		}
		if err := e.audit.Record(ctx, tx, PeerPrincipal(peer.Name), AuditPeerEnrol, peer.ID,
			map[string]string{"name": peer.Name, "kind": peer.Kind, "tags": tagsDetail(peer.Tags), "ipv4": peer.IPv4, "key": wg.Fingerprint(pub), "token": tok.ID, "os": peer.OS, "client_version": req.ClientVersion}); err != nil {
			return err
		}
		result = EnrollResult{Peer: peer, NodeSecret: nodeSecret, Generation: gen}
		e.log.Info("peer enrolled", "peer", peer.Name, "peer_id", peer.ID, "kind", peer.Kind,
			"ipv4", peer.IPv4, "key", wg.Fingerprint(pub), "token", tok.ID, "remote", req.RemoteIP,
			"os", req.OS, "arch", req.Arch, "client_version", req.ClientVersion, "generation", gen)
		return nil
	})
	if err != nil {
		return EnrollResult{}, err
	}
	if e.notify != nil {
		e.notify.Changed()
	}
	return result, nil
}

// checkVersion enforces min (MAJOR.MINOR). Development builds, whose
// version does not start with a number, are always accepted.
func checkVersion(client, minimum string) error {
	if minimum == "" {
		return nil
	}
	cMaj, cMin, ok := parseMajorMinor(client)
	if !ok {
		return nil
	}
	mMaj, mMin, ok := parseMajorMinor(minimum)
	if !ok {
		return nil
	}
	if cMaj < mMaj || (cMaj == mMaj && cMin < mMin) {
		return fmt.Errorf("%w: client %s, server requires at least %s", ErrVersion, client, minimum)
	}
	return nil
}

func parseMajorMinor(v string) (int, int, bool) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(strings.SplitN(parts[1], "-", 2)[0])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return maj, minor, true
}

// parsePublicKey validates a base64 WireGuard public key.
func parsePublicKey(s string) (wg.Key, error) {
	k, err := wg.ParseKey(s)
	if err != nil {
		return wg.Key{}, fmt.Errorf("%w: public_key is not a WireGuard key", ErrValidation)
	}
	return k, nil
}

// platform joins os and arch as "linux/amd64"; either may be empty.
func platform(os, arch string) string {
	switch {
	case os == "":
		return arch
	case arch == "":
		return os
	default:
		return os + "/" + arch
	}
}

// NewerMajorMinor reports whether server is ahead of client in
// MAJOR.MINOR, ignoring a leading "v" and anything after the minor.
// Versions that do not parse (development builds) are never newer.
func NewerMajorMinor(server, client string) bool {
	sMaj, sMin, ok := parseMajorMinor(server)
	if !ok {
		return false
	}
	cMaj, cMin, ok := parseMajorMinor(client)
	if !ok {
		return false
	}
	return sMaj > cMaj || (sMaj == cMaj && sMin > cMin)
}
