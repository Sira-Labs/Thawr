package api

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/sira-labs/thawr/internal/relay"
	"github.com/sira-labs/thawr/internal/wg"
)

// RelaySession serves one authenticated relay connection; the relay
// server implements it.
type RelaySession interface {
	Serve(ctx context.Context, conn net.Conn, key relay.Key) error
}

// handleRelay upgrades GET /relay to the frame stream. The node secret
// is checked before anything past the headers is read, so a wrong
// secret costs the server one lookup and no frame parsing.
func (h *rest) handleRelay(w http.ResponseWriter, r *http.Request) {
	if h.deps.Relay == nil || h.deps.NodeAuth == nil {
		writeError(w, http.StatusNotImplemented, "relay not available")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Authentication comes first: an unauthenticated caller learns
	// nothing about the upgrade, whatever headers it sent.
	secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || secret == "" {
		writeError(w, http.StatusUnauthorized, "node secret required")
		return
	}
	peer, err := h.deps.NodeAuth.PeerByNodeSecret(r.Context(), secret)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid node secret")
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), relay.Protocol) || !headerHasToken(r.Header, "Connection", "upgrade") {
		w.Header().Set("Upgrade", relay.Protocol)
		writeError(w, http.StatusUpgradeRequired, "upgrade to "+relay.Protocol+" required")
		return
	}
	key, err := wg.ParseKey(peer.PublicKey)
	if err != nil {
		h.deps.Logger.Error("relay: peer has an unparsable key", "peer", peer.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "peer key invalid")
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "connection cannot be upgraded")
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hijack failed")
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + relay.Protocol + "\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		_ = conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return
	}
	stream := relay.BufferedConn(conn, rw.Reader)
	if err := h.deps.Relay.Serve(r.Context(), stream, relay.Key(key)); err != nil {
		h.deps.Logger.Debug("relay session ended with error", "peer", peer.Name, "err", err)
	}
	_ = conn.Close()
}

// headerHasToken reports whether a comma-separated header lists token.
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}
