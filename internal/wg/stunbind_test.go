package wg

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/sira-labs/thawr/internal/stun"
)

// fakeBind delivers scripted packets to the device and records sends.
type fakeBind struct {
	incoming [][]byte
	from     conn.Endpoint
	sent     [][]byte
	sentTo   string
}

type fakeEndpoint struct{ addr netip.AddrPort }

func (e fakeEndpoint) ClearSrc()           {}
func (e fakeEndpoint) SrcToString() string { return "" }
func (e fakeEndpoint) DstToString() string { return e.addr.String() }
func (e fakeEndpoint) DstToBytes() []byte  { return nil }
func (e fakeEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e fakeEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (b *fakeBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n := 0
		for i, pkt := range b.incoming {
			if i >= len(bufs) {
				break
			}
			copy(bufs[i], pkt)
			sizes[i] = len(pkt)
			eps[i] = b.from
			n++
		}
		b.incoming = nil
		return n, nil
	}
	return []conn.ReceiveFunc{recv}, 51820, nil
}
func (b *fakeBind) Close() error         { return nil }
func (b *fakeBind) SetMark(uint32) error { return nil }
func (b *fakeBind) BatchSize() int       { return 8 }
func (b *fakeBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	return fakeEndpoint{addr: ap}, err
}
func (b *fakeBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.sent = append(b.sent, bufs...)
	b.sentTo = ep.DstToString()
	return nil
}

func TestSTUNBindFiltersResponses(t *testing.T) {
	from := netip.MustParseAddrPort("198.51.100.1:3478")
	tx := stun.NewTxID()
	wgPacket := make([]byte, 148) // handshake initiation sized
	wgPacket[0] = 1
	inner := &fakeBind{incoming: [][]byte{stun.Response(tx, netip.MustParseAddrPort("203.0.113.9:4000")), wgPacket}, from: fakeEndpoint{addr: from}}
	b := newSTUNBind(inner)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	bufs := [][]byte{make([]byte, 1500), make([]byte, 1500)}
	sizes := make([]int, 2)
	eps := make([]conn.Endpoint, 2)
	n, err := fns[0](bufs, sizes, eps)
	if err != nil || n != 2 {
		t.Fatalf("recv: n=%d err=%v", n, err)
	}
	if sizes[0] != 0 || sizes[1] != len(wgPacket) {
		t.Fatalf("sizes = %v: STUN must be zeroed, WireGuard kept", sizes)
	}
	tr := b.transport()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pkt, gotFrom, err := tr.Recv(ctx)
	if err != nil || gotFrom != from {
		t.Fatalf("Recv: %v from %s", err, gotFrom)
	}
	if gotTx, mapped, err := stun.ParseResponse(pkt); err != nil || gotTx != tx || mapped.Port() != 4000 {
		t.Fatalf("delivered packet: %v tx=%x mapped=%s", err, gotTx, mapped)
	}
	if err := tr.Send(ctx, from, stun.Request(tx)); err != nil {
		t.Fatal(err)
	}
	if len(inner.sent) != 1 || inner.sentTo != from.String() {
		t.Errorf("Send: %d packets to %q", len(inner.sent), inner.sentTo)
	}
}
