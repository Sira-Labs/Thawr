package api

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/sira-labs/thawr/internal/store"
)

// NodeAuth authenticates agent peers by node secret.
type NodeAuth interface {
	PeerByNodeSecret(ctx context.Context, secret string) (store.Peer, error)
}

type peerKey struct{}

// enrollMethod is the only RPC that runs without a node secret.
const enrollMethod = "/thawr.v1.Control/Enroll"

// peerFromContext returns the authenticated peer.
func peerFromContext(ctx context.Context) (store.Peer, bool) {
	p, ok := ctx.Value(peerKey{}).(store.Peer)
	return p, ok
}

// authenticate resolves the bearer node secret into a peer.
func authenticate(ctx context.Context, auth NodeAuth) (context.Context, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	var secret string
	for _, v := range md.Get("authorization") {
		if s, ok := strings.CutPrefix(v, "Bearer "); ok {
			secret = s
		}
	}
	if secret == "" {
		return nil, status.Error(codes.Unauthenticated, "node secret required")
	}
	peer, err := auth.PeerByNodeSecret(ctx, secret)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid node secret")
	}
	return context.WithValue(ctx, peerKey{}, peer), nil
}

func unaryAuth(auth NodeAuth) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info.FullMethod == enrollMethod {
			return handler(ctx, req)
		}
		ctx, err := authenticate(ctx, auth)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func streamAuth(auth NodeAuth) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := authenticate(ss.Context(), auth)
		if err != nil {
			return err
		}
		return handler(srv, &authedStream{ServerStream: ss, ctx: ctx})
	}
}

type authedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authedStream) Context() context.Context { return s.ctx }
