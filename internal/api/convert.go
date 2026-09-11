package api

import (
	"fmt"

	thawrv1 "github.com/thedatadudech/thawr/internal/api/proto/thawr/v1"
	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/lock"
)

func kindToProto(k control.EndpointKind) thawrv1.EndpointKind {
	switch k {
	case control.EndpointLocal:
		return thawrv1.EndpointKind_ENDPOINT_KIND_LOCAL
	case control.EndpointReflexive:
		return thawrv1.EndpointKind_ENDPOINT_KIND_REFLEXIVE
	case control.EndpointStable:
		return thawrv1.EndpointKind_ENDPOINT_KIND_STABLE
	}
	return thawrv1.EndpointKind_ENDPOINT_KIND_UNSPECIFIED
}

func kindFromProto(k thawrv1.EndpointKind) control.EndpointKind {
	switch k {
	case thawrv1.EndpointKind_ENDPOINT_KIND_LOCAL:
		return control.EndpointLocal
	case thawrv1.EndpointKind_ENDPOINT_KIND_REFLEXIVE:
		return control.EndpointReflexive
	case thawrv1.EndpointKind_ENDPOINT_KIND_STABLE:
		return control.EndpointStable
	}
	return 0
}

func endpointsToProto(eps []control.Endpoint) []*thawrv1.Endpoint {
	out := make([]*thawrv1.Endpoint, 0, len(eps))
	for _, e := range eps {
		out = append(out, &thawrv1.Endpoint{Addr: e.Addr.String(), Kind: kindToProto(e.Kind)})
	}
	return out
}

func endpointsFromProto(eps []*thawrv1.Endpoint) ([]control.Endpoint, error) {
	if len(eps) > control.MaxEndpoints {
		return nil, fmt.Errorf("%w: at most %d endpoints", control.ErrValidation, control.MaxEndpoints)
	}
	out := make([]control.Endpoint, 0, len(eps))
	for _, e := range eps {
		ep, err := control.ParseEndpoint(e.GetAddr(), kindFromProto(e.GetKind()))
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, nil
}

// netMapToProto converts the control netmap to its wire form.
func netMapToProto(nm control.NetMap) *thawrv1.NetMap {
	out := &thawrv1.NetMap{
		Generation: nm.Generation,
		Self:       &thawrv1.SelfInfo{Id: nm.SelfID, Name: nm.SelfName, Kind: nm.SelfKind, Ipv4: nm.SelfIPv4.String(), OverlayCidr: nm.Overlay.String(), StunAddrs: append([]string{}, nm.STUN...)},
		Hub:        &thawrv1.HubPeer{PublicKey: nm.Hub.PublicKey, Endpoint: nm.Hub.Endpoint, Signatures: signaturesToProto(nm.Hub.Signatures)},
		Lock:       lockToProto(nm.Lock),
	}
	for _, p := range nm.Hub.AllowedIPs {
		out.Hub.AllowedIps = append(out.Hub.AllowedIps, p.String())
	}
	for _, p := range nm.Peers {
		np := &thawrv1.NetPeer{
			Id: p.ID, Name: p.Name, Kind: p.Kind, Owner: p.Owner, PublicKey: p.PublicKey, Ipv4: p.IPv4.String(),
			Online: p.Online, Endpoints: endpointsToProto(p.Endpoints), Symmetric: p.Symmetric, Keepalive: p.Keepalive, ViaHub: p.ViaHub,
			Signatures: signaturesToProto(p.Signatures),
		}
		for _, a := range p.AllowedIPs {
			np.AllowedIps = append(np.AllowedIps, a.String())
		}
		out.Peers = append(out.Peers, np)
	}
	for _, f := range nm.Filter {
		out.Filter = append(out.Filter, &thawrv1.FilterRule{SrcIpv4: f.SrcIPv4.String(), Proto: f.Proto, PortLo: uint32(f.PortLo), PortHi: uint32(f.PortHi)})
	}
	return out
}

func signaturesToProto(sigs []control.PeerSignature) []*thawrv1.PeerSignature {
	if len(sigs) == 0 {
		return nil
	}
	out := make([]*thawrv1.PeerSignature, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, &thawrv1.PeerSignature{SignerKey: s.Signer.String(), Signature: s.Signature.String()})
	}
	return out
}

// lockToProto converts the signed lock record; nil stays nil, which the
// client reads as "the server offers no record".
func lockToProto(s *lock.Signed) *thawrv1.SignedLockRecord {
	if s == nil {
		return nil
	}
	rec := &thawrv1.LockRecord{Generation: s.Record.Generation, Disabled: s.Record.Disabled}
	for _, sg := range s.Record.Signers {
		rec.Signers = append(rec.Signers, &thawrv1.LockSigner{Key: sg.Key.String(), PeerId: sg.PeerID})
	}
	return &thawrv1.SignedLockRecord{Record: rec, Signature: s.Signature.String()}
}

// lockFromProto parses a signed lock record from the wire. The
// signature itself is checked by lock.Accept, not here.
func lockFromProto(in *thawrv1.SignedLockRecord) (lock.Signed, error) {
	if in == nil || in.GetRecord() == nil {
		return lock.Signed{}, fmt.Errorf("%w: lock record required", control.ErrValidation)
	}
	if len(in.GetRecord().GetSigners()) > lock.MaxSigners {
		return lock.Signed{}, fmt.Errorf("%w: at most %d signers", control.ErrValidation, lock.MaxSigners)
	}
	out := lock.Signed{Record: lock.Record{Generation: in.GetRecord().GetGeneration(), Disabled: in.GetRecord().GetDisabled()}}
	for _, sg := range in.GetRecord().GetSigners() {
		key, err := lock.ParsePublicKey(sg.GetKey())
		if err != nil {
			return lock.Signed{}, fmt.Errorf("%w: signer key: %w", control.ErrValidation, err)
		}
		out.Record.Signers = append(out.Record.Signers, lock.Signer{Key: key, PeerID: sg.GetPeerId()})
	}
	sig, err := lock.ParseSignature(in.GetSignature())
	if err != nil {
		return lock.Signed{}, fmt.Errorf("%w: signature: %w", control.ErrValidation, err)
	}
	out.Signature = sig
	return out, nil
}
