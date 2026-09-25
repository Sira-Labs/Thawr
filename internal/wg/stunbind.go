package wg

import (
	"bytes"
	"context"
	"errors"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/sira-labs/thawr/internal/stun"
)

// stunBind wraps wireguard-go's socket so STUN can share the WireGuard
// port: responses are picked out of the receive path before the device
// sees them (their size is zeroed, which the device skips as too short)
// and requests go out through the same socket.
type stunBind struct {
	conn.Bind
	responses chan stunPacket
}

type stunPacket struct {
	data []byte
	from netip.AddrPort
}

func newSTUNBind(inner conn.Bind) *stunBind {
	return &stunBind{Bind: inner, responses: make(chan stunPacket, 64)}
}

// Open wraps every receive function with the STUN filter.
func (b *stunBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, actual, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = b.filter(fn)
	}
	return wrapped, actual, nil
}

func (b *stunBind) filter(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(bufs, sizes, eps)
		for i := range n {
			if !stun.Is(bufs[i][:sizes[i]]) {
				continue
			}
			pkt := stunPacket{data: bytes.Clone(bufs[i][:sizes[i]])}
			if eps[i] != nil {
				if ap, perr := netip.ParseAddrPort(eps[i].DstToString()); perr == nil {
					pkt.from = ap
				}
			}
			select {
			case b.responses <- pkt:
			default: // nobody is discovering; drop rather than block the device
			}
			sizes[i] = 0
		}
		return n, err
	}
}

func (b *stunBind) transport() stun.Transport { return &bindTransport{bind: b} }

// bindTransport is the stun.Transport view of a stunBind.
type bindTransport struct {
	bind *stunBind
}

func (t *bindTransport) Send(_ context.Context, dst netip.AddrPort, pkt []byte) error {
	ep, err := t.bind.ParseEndpoint(dst.String())
	if err != nil {
		return err
	}
	if err := t.bind.Send([][]byte{pkt}, ep); err != nil {
		return errors.Join(errors.New("wg: stun send through device socket"), err)
	}
	return nil
}

func (t *bindTransport) Recv(ctx context.Context) ([]byte, netip.AddrPort, error) {
	select {
	case p := <-t.bind.responses:
		return p.data, p.from, nil
	case <-ctx.Done():
		return nil, netip.AddrPort{}, ctx.Err()
	}
}

// Close is a no-op: the device owns the socket.
func (t *bindTransport) Close() error { return nil }
