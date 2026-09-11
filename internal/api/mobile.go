package api

import (
	"fmt"
	"net/http"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/dns"
	"github.com/thedatadudech/thawr/internal/wg"
)

// MobileWarning is shown wherever a phone config is displayed: the hub
// terminates the phone's WireGuard session, so the server sees its
// traffic in the clear (threat model T4).
const MobileWarning = "The server decrypts this phone's traffic (threat model T4, docs/THREAT_MODEL.md#t4-compromised-server). " +
	"Scan the QR now; the config is shown once and cannot be retrieved again."

// mobileView is the answer to POST /peers/mobile. Config carries the
// private key and exists only in this response.
type mobileView struct {
	Peer    peerView `json:"peer"`
	Config  string   `json:"config"`
	QRSVG   string   `json:"qr_svg"`
	Warning string   `json:"warning"`
}

// handleCreateMobile creates a static peer and returns its WireGuard
// config once. The service restricts members to their own peers.
func (h *rest) handleCreateMobile(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	var body struct {
		Owner string   `json:"owner"`
		Name  string   `json:"name"`
		Kind  string   `json:"kind"`
		Tags  []string `json:"tags"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := h.deps.Peers.CreateStatic(r.Context(), p, control.StaticRequest{OwnerName: body.Owner, Name: body.Name, Kind: body.Kind, Tags: body.Tags})
	if err != nil {
		h.writeControlError(w, err)
		return
	}
	conf := renderWireGuardConf(res.PrivateKey, res.Peer.IPv4, h.deps.Hub)
	res.PrivateKey = wg.Key{}
	svg, err := qrSVG(conf)
	if err != nil {
		h.deps.Logger.Error("mobile qr", "peer", res.Peer.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "qr rendering failed")
		return
	}
	writeJSON(w, http.StatusCreated, mobileView{
		Peer: h.peerView(r.Context(), res.Peer, map[string]string{}, nil), Config: conf, QRSVG: svg, Warning: MobileWarning,
	})
}

// renderWireGuardConf renders the phone's config for the official
// WireGuard app: its own key and address, the hub resolver with the
// zone as search domain when the server runs one, the hub as the only
// peer.
func renderWireGuardConf(priv wg.Key, ipv4 string, hub HubInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s/32\n", priv.String(), ipv4)
	if hub.DNS.IsValid() {
		fmt.Fprintf(&b, "DNS = %s, %s\n", hub.DNS, dns.Zone)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", hub.PublicKey, hub.Endpoint, hub.Overlay.String())
	return b.String()
}

// qrSVG renders text as a QR code in SVG (one rect per dark module, a
// four-module quiet zone) for the embedded UI, which loads no scripts.
func qrSVG(text string) (string, error) {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("encode: %w", err)
	}
	bitmap := q.Bitmap() // includes the quiet zone
	n := len(bitmap)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="WireGuard config QR code">`, n, n)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y, row := range bitmap {
		for x, dark := range row {
			if dark {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}
