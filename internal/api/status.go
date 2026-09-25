package api

import (
	"context"

	"github.com/sira-labs/thawr/internal/relay"
)

// Status is the JSON body of GET /api/v1/status.
type Status struct {
	Version          string `json:"version"`
	UptimeSeconds    int64  `json:"uptime_seconds"`
	PeerCount        int    `json:"peer_count"`
	NetmapGeneration int64  `json:"netmap_generation"`
	OnlinePeers      int    `json:"online_peers"`
	TLSFingerprint   string `json:"tls_fingerprint"`
	HubPublicKey     string `json:"hub_public_key"`
	// DNSListen is the hub resolver's ip:port, empty when disabled.
	DNSListen string `json:"dns_listen"`
	// Relay holds the packet relay counters.
	Relay relay.Stats `json:"relay"`
}

// StatusSource provides the live status; the server implements it.
type StatusSource interface {
	Status(ctx context.Context) (Status, error)
}
