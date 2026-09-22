package control

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/thedatadudech/thawr/internal/store"
)

// Audit action names (spec 011). The dotted form groups by subject.
const (
	AuditTokenCreate      = "token.create"
	AuditTokenRevoke      = "token.revoke"
	AuditPeerEnrol        = "peer.enrol"
	AuditPeerCreateStatic = "peer.create_static"
	AuditPeerRename       = "peer.rename"
	AuditPeerDelete       = "peer.delete"
	AuditPeerLeave        = "peer.leave"
	AuditPeerRotateKey    = "peer.rotate_key"
	AuditUserCreate       = "user.create"
	AuditLoginOK          = "login.ok"
	AuditLoginFailed      = "login.failed"
	AuditPolicyReload     = "policy.reload"
	AuditRouteAdvertise   = "route.advertise"
	AuditRouteWithdraw    = "route.withdraw"
	AuditRouteApprove     = "route.approve"
	AuditRouteRevoke      = "route.revoke"
)

// Actor roles beyond the user roles.
const (
	RolePeer      = "peer"
	RoleAnonymous = "anonymous"
)

// Auditor appends audit entries for control-plane mutations. A nil
// Auditor records nothing, so services work without one.
type Auditor struct {
	now func() time.Time
}

// NewAuditor builds an auditor with the given clock.
func NewAuditor(now func() time.Time) *Auditor {
	if now == nil {
		now = time.Now
	}
	return &Auditor{now: now}
}

// Record appends one entry through st, which is the transaction-bound
// store when the caller is inside one, so the entry commits or rolls
// back with the mutation. Details must not carry secrets or full keys;
// callers pass fingerprints.
func (a *Auditor) Record(ctx context.Context, st *store.Store, by Principal, action, target string, details map[string]string) error {
	if a == nil {
		return nil
	}
	actor, role := by.Name, by.Role
	if by.Local {
		actor = LocalAdmin.Name
	}
	if actor == "" {
		actor = "unknown"
	}
	if err := st.Audit().Append(ctx, store.AuditEntry{At: a.now(), Actor: actor, ActorRole: role, Action: action, Target: target, Details: details}); err != nil {
		return fmt.Errorf("control: audit %s: %w", action, err)
	}
	return nil
}

// PeerPrincipal is the actor for an action a peer takes for itself.
func PeerPrincipal(name string) Principal {
	return Principal{Name: "peer:" + name, Role: RolePeer}
}

// anonymousPrincipal is the actor of a failed login attempt.
func anonymousPrincipal(name string) Principal {
	return Principal{Name: name, Role: RoleAnonymous}
}

// tagsDetail renders tags for a details map.
func tagsDetail(tags []string) string {
	return strings.Join(tags, ",")
}
