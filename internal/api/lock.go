package api

import (
	"context"
	"errors"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	thawrv1 "github.com/thedatadudech/thawr/internal/api/proto/thawr/v1"
	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/store"
)

// LockOps are the network-lock operations behind the signing RPCs
// (spec 012). Signers are client devices; the server only stores.
type LockOps interface {
	Set(ctx context.Context, by store.Peer, next lock.Signed, sigs []control.PeerSigning) error
	Sign(ctx context.Context, by store.Peer, peerID, publicKey string, signer lock.PublicKey, sig lock.Signature) error
	IsSigner(ctx context.Context, peerID string) (bool, error)
	ListPeers(ctx context.Context) ([]control.LockPeer, control.LockPeer, error)
	ReportKey(peerID, key string)
}

// LockView is what the REST lock endpoint reads.
type LockView interface {
	Current(ctx context.Context) (*lock.Signed, error)
	ListPeers(ctx context.Context) ([]control.LockPeer, control.LockPeer, error)
}

func (s *controlServer) SetLock(ctx context.Context, req *thawrv1.SetLockRequest) (*thawrv1.Empty, error) {
	if s.deps.Lock == nil {
		return nil, status.Error(codes.Unimplemented, "network lock not available")
	}
	me, ok := peerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "node secret required")
	}
	signed, err := lockFromProto(req.GetLock())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if len(req.GetSignatures()) > maxLockSignatures {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d signatures per request", maxLockSignatures)
	}
	sigs := make([]control.PeerSigning, 0, len(req.GetSignatures()))
	for _, sg := range req.GetSignatures() {
		ps, err := signingFromProto(sg)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		sigs = append(sigs, ps)
	}
	if err := s.deps.Lock.Set(ctx, me, signed, sigs); err != nil {
		return nil, s.toStatus(err)
	}
	return &thawrv1.Empty{}, nil
}

// maxLockSignatures bounds the signatures one SetLock may carry.
const maxLockSignatures = 4096

func signingFromProto(sg *thawrv1.SignPeerRequest) (control.PeerSigning, error) {
	if sg.GetPeerId() == "" {
		return control.PeerSigning{}, errors.New("peer_id required")
	}
	signer, err := lock.ParsePublicKey(sg.GetSignerKey())
	if err != nil {
		return control.PeerSigning{}, err
	}
	sig, err := lock.ParseSignature(sg.GetSignature())
	if err != nil {
		return control.PeerSigning{}, err
	}
	return control.PeerSigning{PeerID: sg.GetPeerId(), PublicKey: sg.GetPublicKey(), Signer: signer, Signature: sig}, nil
}

func (s *controlServer) SignPeer(ctx context.Context, req *thawrv1.SignPeerRequest) (*thawrv1.Empty, error) {
	if s.deps.Lock == nil {
		return nil, status.Error(codes.Unimplemented, "network lock not available")
	}
	me, ok := peerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "node secret required")
	}
	ps, err := signingFromProto(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.deps.Lock.Sign(ctx, me, ps.PeerID, ps.PublicKey, ps.Signer, ps.Signature); err != nil {
		return nil, s.toStatus(err)
	}
	return &thawrv1.Empty{}, nil
}

// ListLockPeers answers only a current signer: it is the one RPC that
// shows a peer the whole registry, and only after the lock record the
// signers themselves signed named the caller.
func (s *controlServer) ListLockPeers(ctx context.Context, _ *thawrv1.Empty) (*thawrv1.LockPeers, error) {
	if s.deps.Lock == nil {
		return nil, status.Error(codes.Unimplemented, "network lock not available")
	}
	me, ok := peerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "node secret required")
	}
	signer, err := s.deps.Lock.IsSigner(ctx, me.ID)
	if err != nil {
		return nil, s.toStatus(err)
	}
	if !signer {
		return nil, status.Error(codes.PermissionDenied, "only a signer may list peers for signing")
	}
	peers, hub, err := s.deps.Lock.ListPeers(ctx)
	if err != nil {
		return nil, s.toStatus(err)
	}
	out := &thawrv1.LockPeers{Hub: lockPeerToProto(hub)}
	for _, p := range peers {
		out.Peers = append(out.Peers, lockPeerToProto(p))
	}
	return out, nil
}

func lockPeerToProto(p control.LockPeer) *thawrv1.LockPeer {
	return &thawrv1.LockPeer{Id: p.ID, Name: p.Name, PublicKey: p.PublicKey, Signed: p.Signed, LockKey: p.LockKey, Kind: p.Kind}
}

// lockView is the lock as GET /api/v1/lock renders it.
type lockView struct {
	Enabled    bool             `json:"enabled"`
	Generation uint64           `json:"generation"`
	Signers    []lockSignerView `json:"signers"`
	// Unsigned lists the peers (and "hub") whose current key carries
	// no signature by a signer of the record; empty when disabled.
	Unsigned []string `json:"unsigned"`
}

type lockSignerView struct {
	Peer        string `json:"peer"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
}

// handleShowLock answers GET /api/v1/lock for any authenticated user.
func (h *rest) handleShowLock(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cur, err := h.deps.Lock.Current(ctx)
	if err != nil {
		h.writeControlError(w, err)
		return
	}
	v := lockView{Signers: []lockSignerView{}, Unsigned: []string{}}
	if cur == nil {
		writeJSON(w, http.StatusOK, v)
		return
	}
	v.Generation = cur.Record.Generation
	v.Enabled = cur.Record.Enabled()
	if !v.Enabled {
		writeJSON(w, http.StatusOK, v)
		return
	}
	peers, hub, err := h.deps.Lock.ListPeers(ctx)
	if err != nil {
		h.writeControlError(w, err)
		return
	}
	names := map[string]string{lock.HubID: lock.HubID}
	if !hub.Signed {
		v.Unsigned = append(v.Unsigned, lock.HubID)
	}
	for _, p := range peers {
		names[p.ID] = p.Name
		if !p.Signed {
			v.Unsigned = append(v.Unsigned, p.Name)
		}
	}
	for _, s := range cur.Record.Signers {
		name := names[s.PeerID]
		if name == "" {
			name = s.PeerID
		}
		v.Signers = append(v.Signers, lockSignerView{Peer: name, Key: s.Key.String(), Fingerprint: lock.Fingerprint(s.Key)})
	}
	writeJSON(w, http.StatusOK, v)
}

// signedIndex maps peer id to its signed state while the lock is on;
// nil when the lock is off or the server has none, so peer views omit
// the field.
func (h *rest) signedIndex(ctx context.Context) map[string]bool {
	if h.deps.Lock == nil {
		return nil
	}
	cur, err := h.deps.Lock.Current(ctx)
	if err != nil || cur == nil || !cur.Record.Enabled() {
		return nil
	}
	peers, _, err := h.deps.Lock.ListPeers(ctx)
	if err != nil {
		h.deps.Logger.Warn("list lock peers", "err", err)
		return nil
	}
	idx := make(map[string]bool, len(peers))
	for _, p := range peers {
		idx[p.ID] = p.Signed
	}
	return idx
}
