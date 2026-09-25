package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sira-labs/thawr/internal/dns"
)

// fakeRegistrar records the registrar calls in order; fail makes
// Register fail until cleared, blockUpdate makes Update hang until its
// context ends (a stuck resolver tool).
type fakeRegistrar struct {
	mu          sync.Mutex
	calls       []string
	entries     []dns.Entry
	fail        error
	blockUpdate bool
}

func (f *fakeRegistrar) setFail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = err
}

func (f *fakeRegistrar) Register(_ context.Context, iface string, server netip.Addr) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "register "+iface+" "+server.String())
	if f.fail != nil {
		return dns.MethodHosts, f.fail
	}
	return dns.MethodHosts, nil
}

func (f *fakeRegistrar) Update(ctx context.Context, entries []dns.Entry) error {
	f.mu.Lock()
	f.calls = append(f.calls, "update")
	f.entries = entries
	block := f.blockUpdate
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (f *fakeRegistrar) Unregister(_ context.Context, iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "unregister "+iface)
	return nil
}

func (f *fakeRegistrar) snapshot() ([]string, []dns.Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...), append([]dns.Entry(nil), f.entries...)
}

// loopbackDNS binds the resolver on 127.0.0.1 instead of the overlay
// address the fake device never carries, and remembers where; tests
// can pull the TCP listener away to simulate a dying resolver.
type loopbackDNS struct {
	mu   sync.Mutex
	addr string
	tcp  net.Listener
}

func (l *loopbackDNS) listen(ctx context.Context, _ netip.AddrPort) (net.PacketConn, net.Listener, error) {
	udp, tcp, err := dns.Listen(ctx, netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		return nil, nil, err
	}
	l.mu.Lock()
	l.addr = udp.LocalAddr().String()
	l.tcp = tcp
	l.mu.Unlock()
	return udp, tcp, nil
}

func (l *loopbackDNS) killTCP() {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.tcp.Close()
}

func (l *loopbackDNS) resolver() *net.Resolver {
	l.mu.Lock()
	addr := l.addr
	l.mu.Unlock()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", addr)
	}}
}

// TestDaemonServesNames enrols two peers and resolves self, hub, the
// other peer and a reverse name through the running daemon; the
// registrar sees unregister, register, then an update per netmap, and
// a final unregister on shutdown.
func TestDaemonServesNames(t *testing.T) {
	cp := newControlPlane(t)
	dirA, dirB := t.TempDir(), t.TempDir()
	stA := cp.enrol(dirA, "a")
	reg := &fakeRegistrar{}
	lb := &loopbackDNS{}
	d, _, stopDaemon := startDaemon(t, dirA, func(o *DaemonOptions) {
		o.DNS = DNSOptions{Mode: DNSOn, Registrar: reg, Listen: lb.listen}
	})
	stop := sync.OnceFunc(stopDaemon)
	t.Cleanup(stop)
	waitApplied(t, d, func(nm NetMap) bool { return nm.Hub.PublicKey != "" })
	stB := cp.enrol(dirB, "b")
	waitApplied(t, d, func(nm NetMap) bool { return len(nm.Peers) == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := lb.resolver()
	lookup := func(name string) string {
		ips, err := r.LookupNetIP(ctx, "ip4", name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		return ips[0].String()
	}
	if got := lookup("a.thawr"); got != stA.IPv4 {
		t.Errorf("self: %s, want %s", got, stA.IPv4)
	}
	if got := lookup("b.thawr"); got != stB.IPv4 {
		t.Errorf("peer: %s, want %s", got, stB.IPv4)
	}
	if got := lookup("hub.thawr"); got != "100.64.0.1" {
		t.Errorf("hub: %s", got)
	}
	if names, err := r.LookupAddr(ctx, stB.IPv4); err != nil || len(names) != 1 || names[0] != "b.thawr." {
		t.Errorf("reverse: %v %v", names, err)
	}
	if _, err := r.LookupNetIP(ctx, "ip4", "nobody.thawr"); err == nil || !strings.Contains(err.Error(), "no such host") {
		t.Errorf("unknown name: %v", err)
	}

	lc := NewLocalClient(d.opts.Socket)
	st, err := lc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.DNS == nil || st.DNS.State != DNSServing || st.DNS.Method != dns.MethodHosts || st.DNS.Names != 3 || st.DNS.Listen != stA.IPv4+":53" {
		t.Errorf("dns status: %+v", st.DNS)
	}
	calls, entries := reg.snapshot()
	if len(calls) < 3 || calls[0] != "unregister thawr0" || calls[1] != "register thawr0 "+stA.IPv4 || calls[2] != "update" {
		t.Errorf("registrar calls: %v", calls)
	}
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != "a,b,hub" {
		t.Errorf("entries: %v", names)
	}
	// Ping accepts the zone suffix.
	if _, err := d.Ping(ctx, "nobody.thawr"); !errors.Is(err, ErrUnknownPeer) || !strings.HasSuffix(err.Error(), ": nobody") {
		t.Errorf("ping with suffix: %v", err)
	}

	stop()
	calls, _ = reg.snapshot()
	if calls[len(calls)-1] != "unregister thawr0" {
		t.Errorf("no unregister on shutdown: %v", calls)
	}
}

// TestDaemonDNSOffAndBindFailure: off means no status object; a bind
// failure is reported, not fatal.
func TestDaemonDNSOffAndBindFailure(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	cp.enrol(dir, "a")
	d, _, stop := startDaemon(t, dir, func(o *DaemonOptions) { o.DNS = DNSOptions{Mode: DNSOff} })
	waitApplied(t, d, func(nm NetMap) bool { return nm.Hub.PublicKey != "" })
	if st := d.Status(context.Background()); st.DNS != nil {
		stop()
		t.Fatalf("dns status with --dns off: %+v", st.DNS)
	}
	stop()

	reg := &fakeRegistrar{}
	d, _, stop = startDaemon(t, dir, func(o *DaemonOptions) {
		o.DNS = DNSOptions{Mode: DNSOn, Registrar: reg, Listen: func(context.Context, netip.AddrPort) (net.PacketConn, net.Listener, error) {
			return nil, nil, errors.New("address in use")
		}}
	})
	defer stop()
	// The cached netmap is applied first; wait for the live connection.
	var st Status
	for deadline := time.Now().Add(5 * time.Second); ; {
		st = d.Status(context.Background())
		if st.Server.State == ServerConnected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon not connected after a dns bind failure: %+v", st.Server)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.DNS == nil || st.DNS.State != DNSError || st.DNS.Error != "address in use" || st.DNS.Method != dns.MethodNone {
		t.Errorf("dns status after bind failure: %+v", st.DNS)
	}
	// Nothing was registered: the OS must not route .thawr into a void.
	if calls, _ := reg.snapshot(); len(calls) != 0 {
		t.Errorf("registrar touched after a bind failure: %v", calls)
	}
}

// TestClientResolverAnswersOnlyLocalHost: a peer the policy lets reach
// port 53 gets no answer, so a device's netmap is not disclosed by name.
func TestClientResolverAnswersOnlyLocalHost(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	st := cp.enrol(dir, "a")
	d, _, stop := startDaemon(t, dir)
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return nm.Hub.PublicKey != "" })
	srv := dns.NewServer(d.dnsServerOptions())
	q := dnsQuery(t, "hub.thawr.")
	for _, from := range []string{"100.64.0.200", "192.168.1.5"} {
		if resp, err := srv.Handle(context.Background(), q, netip.MustParseAddr(from), false); err != nil || resp != nil {
			t.Errorf("query from %s answered: %v %v", from, resp, err)
		}
	}
	for _, from := range []string{st.IPv4, "127.0.0.1"} {
		if resp, err := srv.Handle(context.Background(), q, netip.MustParseAddr(from), false); err != nil || resp == nil {
			t.Errorf("query from %s dropped: %v", from, err)
		}
	}
}

// dnsQuery builds a wire-format A query.
func dnsQuery(t *testing.T, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// waitCalls polls the registrar until cond holds on its call list.
func waitCalls(t *testing.T, reg *fakeRegistrar, what string, cond func([]string) bool) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		calls, _ := reg.snapshot()
		if cond(calls) {
			return calls
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: calls %v", what, calls)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestDNSRegistrationRetries: a failed registration is tried again with
// the next netmap instead of being marked done.
func TestDNSRegistrationRetries(t *testing.T) {
	cp := newControlPlane(t)
	dirA, dirB := t.TempDir(), t.TempDir()
	cp.enrol(dirA, "a")
	reg := &fakeRegistrar{fail: errors.New("resolvectl: busy")}
	lb := &loopbackDNS{}
	d, _, stop := startDaemon(t, dirA, func(o *DaemonOptions) {
		o.DNS = DNSOptions{Mode: DNSOn, Registrar: reg, Listen: lb.listen}
	})
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return nm.Hub.PublicKey != "" })
	waitCalls(t, reg, "first registration attempt", func(c []string) bool {
		return len(c) >= 2 && strings.HasPrefix(c[1], "register ")
	})
	st := d.Status(context.Background())
	if st.DNS == nil || st.DNS.Method != dns.MethodNone || st.DNS.Error == "" {
		t.Fatalf("status after failed registration: %+v", st.DNS)
	}
	// The next netmap retries and succeeds.
	reg.setFail(nil)
	cp.enrol(dirB, "b")
	waitApplied(t, d, func(nm NetMap) bool { return len(nm.Peers) == 1 })
	waitCalls(t, reg, "second registration attempt", func(c []string) bool {
		n := 0
		for _, call := range c {
			if strings.HasPrefix(call, "register ") {
				n++
			}
		}
		// Every netmap before the fault cleared retried; the last attempt
		// succeeded and was followed by the entries update.
		return n >= 2 && c[len(c)-1] == "update"
	})
	if st := d.Status(context.Background()); st.DNS == nil || st.DNS.Method != dns.MethodHosts || st.DNS.Error != "" {
		t.Errorf("status after retry: %+v", st.DNS)
	}
}

// TestDNSDeadListenerUnregisters: when the resolver dies underneath the
// running daemon, the OS registration is removed at once.
func TestDNSDeadListenerUnregisters(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	cp.enrol(dir, "a")
	reg := &fakeRegistrar{}
	lb := &loopbackDNS{}
	d, _, stop := startDaemon(t, dir, func(o *DaemonOptions) {
		o.DNS = DNSOptions{Mode: DNSOn, Registrar: reg, Listen: lb.listen}
	})
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return nm.Hub.PublicKey != "" })
	waitCalls(t, reg, "registered", func(c []string) bool {
		return len(c) >= 2 && strings.HasPrefix(c[1], "register ")
	})
	lb.killTCP()
	waitCalls(t, reg, "unregister after the listener died", func(c []string) bool {
		return len(c) >= 3 && c[len(c)-1] == "unregister thawr0"
	})
	st := d.Status(context.Background())
	if st.DNS == nil || st.DNS.State != DNSError || st.DNS.Method != dns.MethodNone {
		t.Errorf("status after the resolver died: %+v", st.DNS)
	}
	if st.Server.State == "" {
		t.Error("daemon gone")
	}
}

// TestDNSCleanupNotBlockedByRegistrar: a registrar call that hangs is
// cut off by OpTimeout, so the cleanup after a dead listener still runs
// within a bounded time instead of queueing behind it forever.
func TestDNSCleanupNotBlockedByRegistrar(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	cp.enrol(dir, "a")
	reg := &fakeRegistrar{blockUpdate: true}
	lb := &loopbackDNS{}
	d, _, stop := startDaemon(t, dir, func(o *DaemonOptions) {
		o.DNS = DNSOptions{Mode: DNSOn, Registrar: reg, Listen: lb.listen, OpTimeout: 300 * time.Millisecond}
	})
	defer stop()
	waitApplied(t, d, func(nm NetMap) bool { return nm.Hub.PublicKey != "" })
	waitCalls(t, reg, "registered and updating", func(c []string) bool {
		return len(c) >= 3 && strings.HasPrefix(c[1], "register ") && c[2] == "update"
	})
	// Update is now hanging under the lock; the listener dies.
	start := time.Now()
	lb.killTCP()
	waitCalls(t, reg, "unregister despite a hanging update", func(c []string) bool {
		return c[len(c)-1] == "unregister thawr0"
	})
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("cleanup took %s behind a hanging registrar call", d)
	}
	if st := d.Status(context.Background()); st.DNS == nil || st.DNS.Method != dns.MethodNone {
		t.Errorf("status after cleanup: %+v", st.DNS)
	}
}

func TestStripZone(t *testing.T) {
	for in, want := range map[string]string{"nas": "nas", "nas.thawr": "nas", "NAS.thawr.": "nas", "nas.thawr.thawr": "nas.thawr", " nas ": "nas"} {
		if got := stripZone(in); got != want {
			t.Errorf("stripZone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewDaemonRejectsBadDNS(t *testing.T) {
	cp := newControlPlane(t)
	dir := t.TempDir()
	cp.enrol(dir, "a")
	if _, err := NewDaemon(DaemonOptions{StateDir: dir, DNS: DNSOptions{Mode: "maybe"}}); err == nil || !strings.Contains(err.Error(), "dns mode") {
		t.Errorf("mode: %v", err)
	}
	if _, err := NewDaemon(DaemonOptions{StateDir: dir, DNS: DNSOptions{Mode: DNSServe, Port: 70000}}); err == nil || !strings.Contains(err.Error(), "port") {
		t.Errorf("port: %v", err)
	}
}
