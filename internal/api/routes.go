package api

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	thawrv1 "github.com/thedatadudech/thawr/internal/api/proto/thawr/v1"
	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/store"
)

// RoutesOps are the advertised-route operations behind the
// AdvertiseRoutes RPC and the routes endpoints (spec 013).
type RoutesOps interface {
	Advertise(ctx context.Context, by store.Peer, prefixes []string) ([]store.PeerRoute, error)
	SetApproved(ctx context.Context, by control.Principal, name, prefix string, approved bool) error
	List(ctx context.Context, by control.Principal, name string) ([]store.PeerRoute, error)
}

// AdvertiseRoutes replaces the caller's advertised prefixes.
func (s *controlServer) AdvertiseRoutes(ctx context.Context, req *thawrv1.AdvertiseRoutesRequest) (*thawrv1.AdvertisedRoutes, error) {
	if s.deps.Routes == nil {
		return nil, status.Error(codes.Unimplemented, "routes not available")
	}
	me, ok := peerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "node secret required")
	}
	if len(req.GetPrefixes()) > control.MaxAdvertisedRoutes {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d routes", control.MaxAdvertisedRoutes)
	}
	rows, err := s.deps.Routes.Advertise(ctx, me, req.GetPrefixes())
	if err != nil {
		return nil, s.toStatus(err)
	}
	out := &thawrv1.AdvertisedRoutes{}
	for _, r := range rows {
		out.Routes = append(out.Routes, &thawrv1.AdvertisedRoute{Prefix: r.Prefix, Approved: r.Approved})
	}
	return out, nil
}

// routeView is one advertised prefix as the REST API shows it.
type routeView struct {
	Prefix       string `json:"prefix"`
	Approved     bool   `json:"approved"`
	ApprovedBy   string `json:"approved_by,omitempty"`
	ApprovedAt   string `json:"approved_at,omitempty"`
	AdvertisedAt string `json:"advertised_at"`
}

func routeViews(rows []store.PeerRoute) []routeView {
	out := make([]routeView, 0, len(rows))
	for _, r := range rows {
		v := routeView{Prefix: r.Prefix, Approved: r.Approved, ApprovedBy: r.ApprovedBy, AdvertisedAt: r.AdvertisedAt.UTC().Format(timeFormat)}
		if r.Approved {
			v.ApprovedAt = r.ApprovedAt.UTC().Format(timeFormat)
		}
		out = append(out, v)
	}
	return out
}

// handleListRoutes answers GET /api/v1/peers/{name}/routes.
func (h *rest) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	rows, err := h.deps.Routes.List(r.Context(), p, r.PathValue("name"))
	if err != nil {
		h.writeControlError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, routeViews(rows))
}

// handleSetRoute answers PUT /api/v1/peers/{name}/routes/{prefix} with
// {"approved": bool}; the prefix is the CIDR text (its slash is part of
// the path).
func (h *rest) handleSetRoute(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	var body struct {
		Approved bool `json:"approved"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	prefix := strings.TrimSpace(r.PathValue("prefix"))
	if err := h.deps.Routes.SetApproved(r.Context(), p, r.PathValue("name"), prefix, body.Approved); err != nil {
		h.writeControlError(w, err)
		return
	}
	rows, err := h.deps.Routes.List(r.Context(), p, r.PathValue("name"))
	if err != nil {
		h.writeControlError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, routeViews(rows))
}
