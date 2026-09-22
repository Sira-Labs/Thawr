package api

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	thawrv1 "github.com/thedatadudech/thawr/internal/api/proto/thawr/v1"
	"github.com/thedatadudech/thawr/internal/control"
)

// TestAdvertiseRoutesRPC checks validation and the reply of the route
// advertisement RPC and that the netmap reports the advertisement.
func TestAdvertiseRoutesRPC(t *testing.T) {
	env := newSyncEnv(t)
	ctx := context.Background()
	gwID, gwSecret := env.enrol("gw")
	if _, err := env.client.AdvertiseRoutes(ctx, &thawrv1.AdvertiseRoutesRequest{Prefixes: []string{"10.1.0.0/24"}}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("without node secret: %v", err)
	}
	bad := [][]string{{"100.64.9.0/24"}, {"10.1.0.1/24"}, {"nope"}, {"fd00::/64"}}
	for _, b := range bad {
		if _, err := env.client.AdvertiseRoutes(authCtx(gwSecret), &thawrv1.AdvertiseRoutesRequest{Prefixes: b}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%v: %v", b, err)
		}
	}
	res, err := env.client.AdvertiseRoutes(authCtx(gwSecret), &thawrv1.AdvertiseRoutesRequest{Prefixes: []string{"10.1.0.0/24", "0.0.0.0/0"}})
	if err != nil {
		t.Fatalf("advertise: %v", err)
	}
	if len(res.GetRoutes()) != 2 || res.GetRoutes()[0].GetApproved() || res.GetRoutes()[1].GetApproved() {
		t.Errorf("reply: %v", res)
	}
	if err := env.routes.SetApproved(ctx, env.admin, "gw", "10.1.0.0/24", true); err != nil {
		t.Fatal(err)
	}
	res, err = env.client.AdvertiseRoutes(authCtx(gwSecret), &thawrv1.AdvertiseRoutesRequest{Prefixes: []string{"10.1.0.0/24", "0.0.0.0/0"}})
	if err != nil {
		t.Fatal(err)
	}
	approved := map[string]bool{}
	for _, r := range res.GetRoutes() {
		approved[r.GetPrefix()] = r.GetApproved()
	}
	if !approved["10.1.0.0/24"] || approved["0.0.0.0/0"] {
		t.Errorf("approval in reply: %v", approved)
	}
	// The gateway's own netmap lists the advertisement.
	stream, err := env.client.Sync(authCtx(gwSecret), &thawrv1.SyncRequest{})
	if err != nil {
		t.Fatal(err)
	}
	nm, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if nm.GetSelf().GetId() != gwID || len(nm.GetSelf().GetAdvertised()) != 2 {
		t.Errorf("advertised in netmap: %v", nm.GetSelf().GetAdvertised())
	}
	if _, err := env.client.AdvertiseRoutes(authCtx(gwSecret), &thawrv1.AdvertiseRoutesRequest{}); err != nil {
		t.Fatalf("withdraw all: %v", err)
	}
	rows, err := env.routes.List(ctx, env.admin, "gw")
	if err != nil || len(rows) != 0 {
		t.Errorf("after withdraw: %v %v", rows, err)
	}
}

// TestRoutesEndpoint covers the REST routes list and approval.
func TestRoutesEndpoint(t *testing.T) {
	var svc *control.RoutesService
	env := newRESTEnv(t, func(d *RESTDeps, e *restEnv) {
		svc = control.NewRoutesService(e.st, d.Logger, time.Now, netip.MustParsePrefix("100.64.0.0/10"))
		d.Routes = svc
	})
	ctx := context.Background()
	gw := enrolPeer(t, env, "markus")
	other := enrolPeer(t, env, "alice")
	_, admin := env.login("markus", "adminpassword")
	_, member := env.login("alice", "alicepassword")
	if _, err := svc.Advertise(ctx, gw, []string{"10.1.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/peers/" + gw.Name + "/routes"
	if rec := env.do(env.handler, session{}, http.MethodGet, path, nil, false); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rec.Code)
	}
	if rec := env.do(env.handler, member, http.MethodGet, path, nil, false); rec.Code != http.StatusNotFound {
		t.Errorf("member lists another owner's peer: %d", rec.Code)
	}
	if rec := env.do(env.handler, member, http.MethodPut, path+"/10.1.0.0/24", map[string]bool{"approved": true}, true); rec.Code != http.StatusForbidden {
		t.Errorf("member approves: %d %s", rec.Code, rec.Body.String())
	}
	rec := env.do(env.handler, admin, http.MethodPut, path+"/10.1.0.0/24", map[string]bool{"approved": true}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	var views []routeView
	decode(t, rec, &views)
	if len(views) != 1 || !views[0].Approved || views[0].ApprovedBy != "markus" || views[0].Prefix != "10.1.0.0/24" {
		t.Errorf("approve reply: %+v", views)
	}
	if rec := env.do(env.handler, admin, http.MethodPut, path+"/10.2.0.0/24", map[string]bool{"approved": true}, true); rec.Code != http.StatusNotFound {
		t.Errorf("approve of an unadvertised prefix: %d", rec.Code)
	}
	if rec := env.do(env.local, session{}, http.MethodPut, path+"/10.1.0.0/24", map[string]bool{"approved": false}, false); rec.Code != http.StatusOK {
		t.Errorf("revoke over the admin socket: %d %s", rec.Code, rec.Body.String())
	}
	rec = env.do(env.handler, admin, http.MethodGet, path, nil, false)
	views = nil
	decode(t, rec, &views)
	if len(views) != 1 || views[0].Approved || views[0].ApprovedBy != "" || views[0].ApprovedAt != "" {
		t.Errorf("after revoke: %+v", views)
	}
	// The peer detail carries the routes; a peer without any has an
	// empty list.
	rec = env.do(env.handler, admin, http.MethodGet, "/api/v1/peers/"+other.Name, nil, false)
	var detail peerDetail
	decode(t, rec, &detail)
	if detail.Routes == nil || len(detail.Routes) != 0 {
		t.Errorf("detail routes of a plain peer: %+v", detail.Routes)
	}
	rec = env.do(env.handler, admin, http.MethodGet, "/api/v1/peers/"+gw.Name, nil, false)
	decode(t, rec, &detail)
	if len(detail.Routes) != 1 {
		t.Errorf("detail routes of the gateway: %+v", detail.Routes)
	}
}
