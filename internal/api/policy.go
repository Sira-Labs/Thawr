package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/sira-labs/thawr/internal/control"
)

// PolicyService is what the policy endpoints need from the server.
type PolicyService interface {
	Show(ctx context.Context) control.PolicyReport
	Check(ctx context.Context, data []byte) control.PolicyReport
	Reload(ctx context.Context, by control.Principal) (control.PolicyReport, error)
	// FilterFor lists the compiled receiver-side rules of one peer.
	FilterFor(ctx context.Context, peerID string) []control.FilterRule
}

// maxPolicyBytes bounds a document sent to /check.
const maxPolicyBytes = 1 << 20

// handleShowPolicy returns the effective policy, its hash and summary.
func (h *rest) handleShowPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.deps.Policy.Show(r.Context()))
}

// handleCheckPolicy validates a document without installing it. The
// answer is 200 with the errors listed, so the UI can show them inline.
func (h *rest) handleCheckPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML string `json:"yaml"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPolicyBytes)
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rep := h.deps.Policy.Check(r.Context(), []byte(body.YAML))
	writeJSON(w, http.StatusOK, struct {
		OK bool `json:"ok"`
		control.PolicyReport
	}{OK: len(rep.Errors) == 0, PolicyReport: rep})
}

// handleReloadPolicy re-reads the policy file: 200 with the report, or
// 400 with the validation errors while the old policy stays active.
func (h *rest) handleReloadPolicy(w http.ResponseWriter, r *http.Request) {
	by, _ := principalFrom(r.Context())
	rep, err := h.deps.Policy.Reload(r.Context(), by)
	if errors.Is(err, control.ErrPolicyInvalid) {
		writeJSON(w, http.StatusBadRequest, struct {
			Error string `json:"error"`
			control.PolicyReport
		}{Error: "policy invalid; previous policy kept", PolicyReport: rep})
		return
	}
	if err != nil {
		h.writeControlError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
