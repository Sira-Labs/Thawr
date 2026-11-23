package control

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/store"
)

const (
	testRelayURL = "https://relay-riyadh.example.com:443"
	testRelayFP  = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	otherRelayFP = "sha256:" + "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

type relayEnv struct {
	*enrollEnv
	relays *Relays
	notify *countNotifier
	member Principal
	// epochs holds the attachment epoch of every relay online() attached.
	epochs map[string]uint64
}

func newRelayEnv(t *testing.T) *relayEnv {
	t.Helper()
	env := newEnrollEnv(t, "100.64.0.0/10")
	n := &countNotifier{}
	relays := NewRelays(env.st, env.clk.Now, quietLogger()).WithAuditor(NewAuditor(env.clk.Now)).WithNotifier(n)
	env.registry.WithTicketForgetter(relays)
	return &relayEnv{enrollEnv: env, relays: relays, notify: n, epochs: map[string]uint64{},
		member: asPrincipal(mustUser(t, env.users, "lena", store.RoleMember))}
}

// register creates a token for name and registers a relay with it.
func (e *relayEnv) register(t *testing.T, name string) RegisteredRelay {
	t.Helper()
	ctx := context.Background()
	tok, err := e.relays.CreateToken(ctx, e.admin, name, 0)
	if err != nil {
		t.Fatalf("relay token: %v", err)
	}
	reg, err := e.relays.Register(ctx, RelayRegistration{Token: tok.Secret, URL: testRelayURL, Fingerprint: testRelayFP, Version: "0.2.0"})
	if err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	return reg
}

// online registers a relay and attaches it.
func (e *relayEnv) online(t *testing.T, name string) store.Relay {
	t.Helper()
	reg := e.register(t, name)
	epoch, err := e.relays.Attach(context.Background(), reg.Relay.ID, RelayHello{URL: testRelayURL, Fingerprint: testRelayFP, Version: "0.2.0"})
	if err != nil {
		t.Fatalf("attach %s: %v", name, err)
	}
	e.epochs[reg.Relay.ID] = epoch
	return reg.Relay
}

func (e *relayEnv) peer(t *testing.T, hostname string) store.Peer {
	t.Helper()
	return e.enrolled(t, hostname, true)
}

// enrolled enrols a device whose client does or does not say it can
// use relay nodes.
func (e *relayEnv) enrolled(t *testing.T, hostname string, relayNodes bool) store.Peer {
	t.Helper()
	res, err := e.enroller.Enroll(context.Background(), EnrollRequest{
		Token: e.token(t, TokenRequest{}), PublicKey: newPubKey(t), Hostname: hostname, OS: "linux", Arch: "amd64",
		ClientVersion: "0.2.0", RelayNodes: relayNodes,
	})
	if err != nil {
		t.Fatalf("enroll %s: %v", hostname, err)
	}
	return res.Peer
}

func (e *relayEnv) generation(t *testing.T) int64 {
	t.Helper()
	g, err := e.st.Meta().Generation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestRelayRegister(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	tok, err := env.relays.CreateToken(ctx, env.admin, "riyadh-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Secret, RelayTokenPrefix) || tok.Token.SecretHash != hashSecret(tok.Secret) ||
		!tok.Token.ExpiresAt.Equal(env.clk.Now().Add(DefaultRelayTokenTTL)) {
		t.Errorf("token: %+v", tok.Token)
	}
	reg, err := env.relays.Register(ctx, RelayRegistration{Token: tok.Secret, URL: testRelayURL, Fingerprint: testRelayFP, Version: "0.2.0"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if reg.Relay.Name != "riyadh-1" || reg.Relay.URL != testRelayURL || reg.Secret == "" ||
		reg.Relay.SecretHash != hashSecret(reg.Secret) || strings.Contains(reg.Relay.SecretHash, reg.Secret) {
		t.Errorf("registered: %+v", reg.Relay)
	}
	got, err := env.relays.Authenticate(ctx, reg.Secret)
	if err != nil || got.ID != reg.Relay.ID {
		t.Errorf("authenticate: %+v %v", got, err)
	}
	for _, bad := range []string{"", "nope", tok.Secret} {
		if _, err := env.relays.Authenticate(ctx, bad); !errors.Is(err, ErrForbidden) {
			t.Errorf("authenticate(%q): %v", bad, err)
		}
	}
	// One time only.
	if _, err := env.relays.Register(ctx, RelayRegistration{Token: tok.Secret, Name: "riyadh-2", URL: testRelayURL, Fingerprint: testRelayFP}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("second use: %v", err)
	}
	// Registered is not online: nothing lists it for devices yet.
	if on, err := env.relays.Online(ctx); err != nil || len(on) != 0 {
		t.Errorf("online before attach: %v %v", on, err)
	}
	entries, err := env.st.Audit().List(ctx, store.AuditQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		if strings.HasPrefix(e.Action, "relay.") {
			actions = append(actions, e.Action+" by "+e.Actor+"/"+e.ActorRole)
			for _, v := range e.Details {
				if strings.Contains(v, tok.Secret) || strings.Contains(v, reg.Secret) || v == testRelayFP {
					t.Errorf("audit details of %s carry a secret or a full fingerprint: %v", e.Action, e.Details)
				}
			}
		}
	}
	want := []string{"relay.register by relay:riyadh-1/relay", "relay.token by markus/admin"}
	if strings.Join(actions, "; ") != strings.Join(want, "; ") {
		t.Errorf("audit: %v, want %v", actions, want)
	}
}

func TestRelayRegisterValidation(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	env.register(t, "taken")
	cases := []struct {
		name      string
		tokenName string
		req       RelayRegistration
		want      error
	}{
		{"http url", "", RelayRegistration{Name: "a", URL: "http://r.example.com:443", Fingerprint: testRelayFP}, ErrValidation},
		{"no port", "", RelayRegistration{Name: "a", URL: "https://r.example.com", Fingerprint: testRelayFP}, ErrValidation},
		{"port out of range", "", RelayRegistration{Name: "a", URL: "https://r.example.com:70000", Fingerprint: testRelayFP}, ErrValidation},
		{"path", "", RelayRegistration{Name: "a", URL: "https://r.example.com:443/relay", Fingerprint: testRelayFP}, ErrValidation},
		{"query", "", RelayRegistration{Name: "a", URL: "https://r.example.com:443?x=1", Fingerprint: testRelayFP}, ErrValidation},
		{"userinfo", "", RelayRegistration{Name: "a", URL: "https://u:p@r.example.com:443", Fingerprint: testRelayFP}, ErrValidation},
		{"no host", "", RelayRegistration{Name: "a", URL: "https://:443", Fingerprint: testRelayFP}, ErrValidation},
		{"short fingerprint", "", RelayRegistration{Name: "a", URL: testRelayURL, Fingerprint: "sha256:abcd"}, ErrValidation},
		{"upper-case fingerprint", "", RelayRegistration{Name: "a", URL: testRelayURL, Fingerprint: strings.ToUpper(testRelayFP)}, ErrValidation},
		{"no name anywhere", "", RelayRegistration{URL: testRelayURL, Fingerprint: testRelayFP}, ErrValidation},
		{"bad name", "", RelayRegistration{Name: "Not A Label", URL: testRelayURL, Fingerprint: testRelayFP}, ErrValidation},
		{"hub", "", RelayRegistration{Name: HubName, URL: testRelayURL, Fingerprint: testRelayFP}, ErrValidation},
		{"name taken", "", RelayRegistration{Name: "taken", URL: testRelayURL, Fingerprint: testRelayFP}, ErrValidation},
		{"name differs from the token's", "berlin-1", RelayRegistration{Name: "berlin-2", URL: testRelayURL, Fingerprint: testRelayFP}, ErrValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := env.relays.CreateToken(ctx, env.admin, tc.tokenName, 0)
			if err != nil {
				t.Fatal(err)
			}
			tc.req.Token = tok.Secret
			if _, err := env.relays.Register(ctx, tc.req); !errors.Is(err, tc.want) {
				t.Fatalf("Register: %v, want %v", err, tc.want)
			}
			// A refused registration does not burn the token.
			tc.req.Name, tc.req.URL, tc.req.Fingerprint = tc.tokenName, testRelayURL, testRelayFP
			if tc.req.Name == "" {
				tc.req.Name = "ok-" + tok.Token.ID[3:]
			}
			if _, err := env.relays.Register(ctx, tc.req); err != nil {
				t.Errorf("token unusable after a refused registration: %v", err)
			}
		})
	}
}

func TestRelayTokenRules(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	if _, err := env.relays.CreateToken(ctx, env.member, "x", 0); !errors.Is(err, ErrForbidden) {
		t.Errorf("member creating a relay token: %v", err)
	}
	if _, err := env.relays.CreateToken(ctx, env.admin, "Bad Name", 0); !errors.Is(err, ErrValidation) {
		t.Errorf("bad name: %v", err)
	}
	if _, err := env.relays.CreateToken(ctx, env.admin, "", -time.Second); !errors.Is(err, ErrValidation) {
		t.Errorf("negative ttl: %v", err)
	}
	if _, err := env.relays.CreateToken(ctx, env.admin, "", MaxRelayTokenTTL+time.Second); !errors.Is(err, ErrValidation) {
		t.Errorf("ttl over the maximum: %v", err)
	}
	if _, err := env.relays.CreateToken(ctx, LocalAdmin, "", time.Minute); err != nil {
		t.Errorf("local admin: %v", err)
	}
	tok, err := env.relays.CreateToken(ctx, env.admin, "", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Valid one second before its expiry, not at it.
	env.clk.Advance(10 * time.Minute)
	req := RelayRegistration{Token: tok.Secret, Name: "late", URL: testRelayURL, Fingerprint: testRelayFP}
	if _, err := env.relays.Register(ctx, req); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired token: %v", err)
	}
}

// TestRelayTokenKindsDoNotMix: a peer token registers no relay and a
// relay token enrols no peer, and both refusals read the same.
func TestRelayTokenKindsDoNotMix(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	peerToken := env.token(t, TokenRequest{})
	_, errRelay := env.relays.Register(ctx, RelayRegistration{Token: peerToken, Name: "sneaky", URL: testRelayURL, Fingerprint: testRelayFP})
	if !errors.Is(errRelay, ErrInvalidToken) {
		t.Errorf("peer token at Register: %v", errRelay)
	}
	relayToken, err := env.relays.CreateToken(ctx, env.admin, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	_, errPeer := env.enroll(t, relayToken.Secret, "box")
	if !errors.Is(errPeer, ErrInvalidToken) {
		t.Errorf("relay token at Enroll: %v", errPeer)
	}
	if errRelay != nil && errPeer != nil && errRelay.Error() != errPeer.Error() {
		t.Errorf("the two refusals differ: %q vs %q", errRelay, errPeer)
	}
	// Neither attempt used up the other kind's token.
	if _, err := env.enroll(t, peerToken, "box"); err != nil {
		t.Errorf("peer token after the refused registration: %v", err)
	}
	if _, err := env.relays.Register(ctx, RelayRegistration{Token: relayToken.Secret, Name: "real", URL: testRelayURL, Fingerprint: testRelayFP}); err != nil {
		t.Errorf("relay token after the refused enrolment: %v", err)
	}
}

func TestRelayOnlineOffline(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	reg := env.register(t, "riyadh-1")
	id := reg.Relay.ID
	gen, woke := env.generation(t), env.notify.n

	if err := env.relays.Heartbeat(ctx, id, env.epochs[id], RelayStats{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("heartbeat before attach: %v", err)
	}
	epoch, err := env.relays.Attach(ctx, id, RelayHello{URL: testRelayURL, Fingerprint: testRelayFP, Version: "0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	env.epochs[id] = epoch
	if env.generation(t) != gen+1 || env.notify.n != woke+1 {
		t.Errorf("attach: generation %d (was %d), notified %d (was %d)", env.generation(t), gen, env.notify.n, woke)
	}
	on, err := env.relays.Online(ctx)
	if err != nil || len(on) != 1 || on[0].ID != id {
		t.Fatalf("online after attach: %+v %v", on, err)
	}

	// Heartbeats keep it online and bump nothing.
	env.clk.Advance(10 * time.Second)
	if err := env.relays.Heartbeat(ctx, id, env.epochs[id], RelayStats{Sessions: 2, Bytes: 4096}); err != nil {
		t.Fatal(err)
	}
	if n, err := env.relays.Sweep(ctx); err != nil || n != 0 {
		t.Errorf("sweep while alive: %d %v", n, err)
	}
	if env.generation(t) != gen+1 {
		t.Errorf("a heartbeat moved the generation to %d", env.generation(t))
	}
	st, err := env.relays.Get(ctx, env.admin, "riyadh-1")
	if err != nil || !st.Online || st.Stats.Sessions != 2 || st.Stats.Bytes != 4096 {
		t.Errorf("status: %+v %v", st, err)
	}

	// Exactly at the window it is still online; one second later Online
	// leaves it out even before a sweep, and the sweep bumps once.
	env.clk.Advance(RelayOnlineWindow)
	if on, _ := env.relays.Online(ctx); len(on) != 1 {
		t.Error("offline at exactly the window")
	}
	env.clk.Advance(time.Second)
	if on, _ := env.relays.Online(ctx); len(on) != 0 {
		t.Error("still listed after the window, before a sweep")
	}
	if n, err := env.relays.Sweep(ctx); err != nil || n != 1 {
		t.Errorf("sweep: %d %v", n, err)
	}
	if n, err := env.relays.Sweep(ctx); err != nil || n != 0 {
		t.Errorf("second sweep: %d %v", n, err)
	}
	if env.generation(t) != gen+2 {
		t.Errorf("generation after going offline: %d, want %d", env.generation(t), gen+2)
	}
	st, _ = env.relays.Get(ctx, env.admin, "riyadh-1")
	if st.Online || !st.Since.Equal(env.clk.Now()) {
		t.Errorf("status after sweep: %+v", st)
	}

	// The next heartbeat brings it back; closing the stream takes it away.
	if err := env.relays.Heartbeat(ctx, id, env.epochs[id], RelayStats{}); err != nil {
		t.Fatal(err)
	}
	if on, _ := env.relays.Online(ctx); len(on) != 1 || env.generation(t) != gen+3 {
		t.Errorf("after the returning heartbeat: online %d generation %d", len(on), env.generation(t))
	}
	if err := env.relays.Detach(ctx, id, epoch); err != nil {
		t.Fatal(err)
	}
	if on, _ := env.relays.Online(ctx); len(on) != 0 || env.generation(t) != gen+4 {
		t.Errorf("after detach: online %d generation %d", len(on), env.generation(t))
	}
	if err := env.relays.Detach(ctx, id, epoch); err != nil || env.generation(t) != gen+4 {
		t.Errorf("second detach: %v, generation %d", err, env.generation(t))
	}
	stored, err := env.st.Relays().GetByID(ctx, id)
	if err != nil || stored.LastSeenAt == nil || !stored.LastSeenAt.Equal(env.clk.Now()) {
		t.Errorf("last seen: %+v %v", stored, err)
	}
}

func TestRelayAttachReplacesEndpoint(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	reg := env.register(t, "riyadh-1")
	hello := RelayHello{URL: "https://moved.example.com:8443", Fingerprint: otherRelayFP, Version: "0.2.1"}
	if _, err := env.relays.Attach(ctx, reg.Relay.ID, hello); err != nil {
		t.Fatal(err)
	}
	on, err := env.relays.Online(ctx)
	if err != nil || len(on) != 1 || on[0].URL != hello.URL || on[0].TLSFingerprint != otherRelayFP || on[0].Version != "0.2.1" {
		t.Errorf("after attach with a new endpoint: %+v %v", on, err)
	}
	if _, err := env.relays.Attach(ctx, reg.Relay.ID, RelayHello{URL: "http://x:1", Fingerprint: otherRelayFP}); !errors.Is(err, ErrValidation) {
		t.Errorf("attach with a bad url: %v", err)
	}
	if _, err := env.relays.Attach(ctx, "rl_missing", hello); !errors.Is(err, ErrNotFound) {
		t.Errorf("attach of an unknown relay: %v", err)
	}
}

func TestRelayListAndDelete(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	a := env.online(t, "riyadh-1")
	env.register(t, "berlin-1")
	p := env.peer(t, "box")
	grants, err := env.relays.Tickets(ctx, p.ID)
	if err != nil || len(grants) != 1 {
		t.Fatalf("tickets: %v %v", grants, err)
	}

	if _, err := env.relays.List(ctx, env.member); !errors.Is(err, ErrForbidden) {
		t.Errorf("member listing relays: %v", err)
	}
	list, err := env.relays.List(ctx, env.admin)
	if err != nil || len(list) != 2 || list[0].Relay.Name != "berlin-1" || list[0].Online || !list[1].Online {
		t.Fatalf("list: %+v %v", list, err)
	}
	if _, err := env.relays.Get(ctx, env.admin, "nowhere"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get of an unknown relay: %v", err)
	}
	if _, err := env.relays.Delete(ctx, env.member, "riyadh-1"); !errors.Is(err, ErrForbidden) {
		t.Errorf("member deleting a relay: %v", err)
	}
	if _, err := env.relays.Delete(ctx, env.admin, "nowhere"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete of an unknown relay: %v", err)
	}

	gen := env.generation(t)
	gone, err := env.relays.Delete(ctx, env.admin, "riyadh-1")
	if err != nil || gone.ID != a.ID {
		t.Fatalf("delete: %+v %v", gone, err)
	}
	if env.generation(t) != gen+1 {
		t.Errorf("generation after delete: %d, want %d", env.generation(t), gen+1)
	}
	if on, _ := env.relays.Online(ctx); len(on) != 0 {
		t.Errorf("deleted relay still online: %+v", on)
	}
	if _, err := env.relays.Admit(ctx, a.ID, grants[0].Ticket); !errors.Is(err, ErrForbidden) {
		t.Errorf("ticket of a deleted relay: %v", err)
	}
	if err := env.relays.Heartbeat(ctx, a.ID, env.epochs[a.ID], RelayStats{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("heartbeat of a deleted relay: %v", err)
	}
	if grants, err := env.relays.Tickets(ctx, p.ID); err != nil || len(grants) != 0 {
		t.Errorf("tickets after the only online relay is gone: %v %v", grants, err)
	}
}

func TestTicketIssueAndRenew(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	relay := env.online(t, "riyadh-1")
	alice, bob := env.peer(t, "alice"), env.peer(t, "bob")
	// beat keeps the relay online while the clock moves.
	beat := func(d time.Duration) {
		t.Helper()
		for d > 0 {
			step := min(d, RelayOnlineWindow)
			env.clk.Advance(step)
			d -= step
			if err := env.relays.Heartbeat(ctx, relay.ID, env.epochs[relay.ID], RelayStats{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	one := func(peerID string) RelayTicketGrant {
		t.Helper()
		g, err := env.relays.Tickets(ctx, peerID)
		if err != nil || len(g) != 1 {
			t.Fatalf("tickets for %s: %v %v", peerID, g, err)
		}
		return g[0]
	}

	first := one(alice.ID)
	if len(first.Ticket) != TicketLen || first.Relay.ID != relay.ID || !first.Expires.Equal(env.clk.Now().Add(DefaultTicketTTL)) {
		t.Fatalf("first grant: relay %s, %d bytes, expires %s", first.Relay.ID, len(first.Ticket), first.Expires)
	}
	if got := one(bob.ID); bytes.Equal(got.Ticket, first.Ticket) {
		t.Fatal("two peers were handed the same ticket")
	}
	// Only the hash is stored.
	row, err := env.st.RelayTickets().GetByHash(ctx, hashSecret(string(first.Ticket)))
	if err != nil || row.PeerID != alice.ID || row.RelayID != relay.ID {
		t.Fatalf("stored ticket: %+v %v", row, err)
	}
	if _, err := env.st.RelayTickets().GetByHash(ctx, string(first.Ticket)); !errors.Is(err, store.ErrNotFound) {
		t.Error("the ticket itself is a key in the table")
	}

	// The same ticket until half its lifetime, a new one from then on.
	beat(DefaultTicketTTL/2 - time.Second)
	if got := one(alice.ID); !bytes.Equal(got.Ticket, first.Ticket) {
		t.Error("ticket replaced before half its lifetime")
	}
	beat(time.Second)
	second := one(alice.ID)
	if bytes.Equal(second.Ticket, first.Ticket) {
		t.Fatal("ticket not replaced at half its lifetime")
	}
	// A caller cannot change the cached ticket through the slice it got.
	second.Ticket[0] ^= 0xff
	if again := one(alice.ID); bytes.Equal(again.Ticket, second.Ticket) {
		t.Error("the grant aliases the cached ticket")
	}
	second.Ticket[0] ^= 0xff

	// Both admit until the first expires; then only the second.
	if p, err := env.relays.Admit(ctx, relay.ID, first.Ticket); err != nil || p.ID != alice.ID {
		t.Errorf("replaced ticket before its expiry: %+v %v", p, err)
	}
	beat(DefaultTicketTTL/2 - time.Second)
	if _, err := env.relays.Admit(ctx, relay.ID, first.Ticket); err != nil {
		t.Errorf("one second before expiry: %v", err)
	}
	beat(time.Second)
	if _, err := env.relays.Admit(ctx, relay.ID, first.Ticket); !errors.Is(err, ErrForbidden) {
		t.Errorf("at expiry: %v", err)
	}
	if p, err := env.relays.Admit(ctx, relay.ID, second.Ticket); err != nil || p.ID != alice.ID {
		t.Errorf("current ticket: %+v %v", p, err)
	}
	// Issuing again clears the expired row.
	one(alice.ID)
	if _, err := env.st.RelayTickets().GetByHash(ctx, hashSecret(string(first.Ticket))); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired ticket row not pruned: %v", err)
	}
}

func TestTicketAdmit(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	a, b := env.online(t, "riyadh-1"), env.online(t, "berlin-1")
	alice := env.peer(t, "alice")
	grants, err := env.relays.Tickets(ctx, alice.ID)
	if err != nil || len(grants) != 2 || grants[0].Relay.ID != b.ID || grants[1].Relay.ID != a.ID {
		t.Fatalf("grants ordered by relay name: %+v %v", grants, err)
	}
	forBerlin, forRiyadh := grants[0].Ticket, grants[1].Ticket
	if p, err := env.relays.Admit(ctx, a.ID, forRiyadh); err != nil || p.ID != alice.ID || p.PublicKey != alice.PublicKey {
		t.Errorf("admit: %+v %v", p, err)
	}
	// A ticket is not consumed by use.
	if _, err := env.relays.Admit(ctx, a.ID, forRiyadh); err != nil {
		t.Errorf("second admit with the same ticket: %v", err)
	}
	for name, tc := range map[string]struct {
		relay  string
		ticket []byte
	}{
		"another relay's ticket": {a.ID, forBerlin},
		"unknown ticket":         {a.ID, bytes.Repeat([]byte{7}, TicketLen)},
		"short ticket":           {a.ID, forRiyadh[:TicketLen-1]},
		"empty ticket":           {a.ID, nil},
		"unknown relay":          {"rl_nope", forRiyadh},
	} {
		if _, err := env.relays.Admit(ctx, tc.relay, tc.ticket); !errors.Is(err, ErrForbidden) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestTicketsDieWithKeyAndPeer: a rotated key and a deleted peer take
// their tickets along, and the next netmap gets fresh ones rather than
// the dead ones from memory.
func TestTicketsDieWithKeyAndPeer(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	relay := env.online(t, "riyadh-1")
	alice, bob := env.peer(t, "alice"), env.peer(t, "bob")
	ticket := func(peerID string) []byte {
		t.Helper()
		g, err := env.relays.Tickets(ctx, peerID)
		if err != nil || len(g) != 1 {
			t.Fatalf("tickets: %v %v", g, err)
		}
		return g[0].Ticket
	}
	old, bobs := ticket(alice.ID), ticket(bob.ID)

	if _, err := env.registry.RotateKey(ctx, alice.ID, newPubKey(t), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := env.relays.Admit(ctx, relay.ID, old); !errors.Is(err, ErrForbidden) {
		t.Errorf("ticket from before the rotation: %v", err)
	}
	fresh := ticket(alice.ID)
	if bytes.Equal(fresh, old) {
		t.Fatal("the dead ticket was handed out again")
	}
	if _, err := env.relays.Admit(ctx, relay.ID, fresh); err != nil {
		t.Errorf("ticket issued after the rotation: %v", err)
	}
	if _, err := env.relays.Admit(ctx, relay.ID, bobs); err != nil {
		t.Errorf("another peer's ticket after alice rotated: %v", err)
	}

	if err := env.registry.Delete(ctx, env.admin, bob.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := env.relays.Admit(ctx, relay.ID, bobs); !errors.Is(err, ErrForbidden) {
		t.Errorf("ticket of a deleted peer: %v", err)
	}
}

func TestTicketTTLBounds(t *testing.T) {
	env := newRelayEnv(t)
	for _, ttl := range []time.Duration{0, MinTicketTTL - time.Second, MaxTicketTTL + time.Second} {
		if _, err := env.relays.WithTicketTTL(ttl); !errors.Is(err, ErrValidation) {
			t.Errorf("ttl %s: %v", ttl, err)
		}
	}
	r, err := env.relays.WithTicketTTL(MinTicketTTL)
	if err != nil {
		t.Fatal(err)
	}
	relay := env.online(t, "riyadh-1")
	p := env.peer(t, "box")
	g, err := r.Tickets(context.Background(), p.ID)
	if err != nil || len(g) != 1 || g[0].Relay.ID != relay.ID || !g[0].Expires.Equal(env.clk.Now().Add(MinTicketTTL)) {
		t.Errorf("grant with the shortest lifetime: %+v %v", g, err)
	}
}

// TestRelayHeartbeatAfterStaleGap: a relay whose heartbeats paused for
// longer than the window is left out by Online at once. When it beats
// again before any sweep ran, devices must hear of it: the heartbeat
// moves the generation although no sweep ever took the relay offline.
func TestRelayHeartbeatAfterStaleGap(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	relay := env.online(t, "riyadh-1")
	gen, woke := env.generation(t), env.notify.n
	env.clk.Advance(RelayOnlineWindow + time.Second)
	if on, _ := env.relays.Online(ctx); len(on) != 0 {
		t.Fatal("relay listed after the window")
	}
	if err := env.relays.Heartbeat(ctx, relay.ID, env.epochs[relay.ID], RelayStats{Sessions: 1}); err != nil {
		t.Fatal(err)
	}
	if on, _ := env.relays.Online(ctx); len(on) != 1 {
		t.Error("relay not back after its heartbeat")
	}
	if env.generation(t) != gen+1 || env.notify.n != woke+1 {
		t.Errorf("generation %d (was %d), notified %d (was %d)", env.generation(t), gen, env.notify.n, woke)
	}
	// The sweep that follows has nothing left to do.
	if n, err := env.relays.Sweep(ctx); err != nil || n != 0 {
		t.Errorf("sweep after the recovery: %d %v", n, err)
	}
	st, _ := env.relays.Get(ctx, env.admin, "riyadh-1")
	if !st.Online || st.Stats.Sessions != 1 || !st.Since.Equal(env.clk.Now()) {
		t.Errorf("status: %+v", st)
	}
}

// TestRelayLivenessRetriesAfterFailedWrite: when the generation cannot
// be written, a liveness change is not applied in memory either, so the
// next call finds the same condition and publishes it.
func TestRelayLivenessRetriesAfterFailedWrite(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	dead, cancel := context.WithCancel(ctx)
	cancel()
	relay := env.online(t, "riyadh-1")
	listed := func() bool {
		st, err := env.relays.Get(ctx, env.admin, "riyadh-1")
		if err != nil {
			t.Fatal(err)
		}
		return st.Online
	}

	// Sweep: the failed attempt leaves the relay for the next sweep.
	env.clk.Advance(RelayOnlineWindow + time.Second)
	gen := env.generation(t)
	if n, err := env.relays.Sweep(dead); err == nil || n != 0 {
		t.Fatalf("sweep with a failing store: %d %v", n, err)
	}
	if env.generation(t) != gen {
		t.Fatalf("generation moved to %d on a failed sweep", env.generation(t))
	}
	if n, err := env.relays.Sweep(ctx); err != nil || n != 1 || env.generation(t) != gen+1 {
		t.Fatalf("retried sweep: %d %v, generation %d", n, err, env.generation(t))
	}

	// Heartbeat: the failed recovery is tried again by the next beat.
	if err := env.relays.Heartbeat(dead, relay.ID, env.epochs[relay.ID], RelayStats{}); err == nil {
		t.Fatal("heartbeat with a failing store reported success")
	}
	if listed() || env.generation(t) != gen+1 {
		t.Fatalf("after the failed recovery: online %v, generation %d", listed(), env.generation(t))
	}
	if err := env.relays.Heartbeat(ctx, relay.ID, env.epochs[relay.ID], RelayStats{}); err != nil || !listed() || env.generation(t) != gen+2 {
		t.Fatalf("retried recovery: %v, online %v, generation %d", err, listed(), env.generation(t))
	}

	// Detach: the failed attempt leaves the relay online for a retry.
	if err := env.relays.Detach(dead, relay.ID, env.epochs[relay.ID]); err == nil {
		t.Fatal("detach with a failing store reported success")
	}
	if !listed() || env.generation(t) != gen+2 {
		t.Fatalf("after the failed detach: online %v, generation %d", listed(), env.generation(t))
	}
	if err := env.relays.Detach(ctx, relay.ID, env.epochs[relay.ID]); err != nil || listed() || env.generation(t) != gen+3 {
		t.Fatalf("retried detach: %v, online %v, generation %d", err, listed(), env.generation(t))
	}
}

// TestTicketsFailedPruneIsRetried: a prune that could not run is due
// again at the next call, not a minute later.
func TestTicketsFailedPruneIsRetried(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	dead, cancel := context.WithCancel(ctx)
	cancel()
	env.online(t, "riyadh-1")
	p := env.peer(t, "box")
	if _, err := env.relays.Tickets(dead, p.ID); err == nil {
		t.Fatal("tickets with a failing store reported success")
	}
	g, err := env.relays.Tickets(ctx, p.ID)
	if err != nil || len(g) != 1 {
		t.Fatalf("tickets after the failure: %v %v", g, err)
	}
}

// TestRelayReattachReplaces: a relay that reconnects before its old
// stream is noticed dead stays online when that old stream ends, and
// the old stream can tell it was replaced.
func TestRelayReattachReplaces(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	relay := env.online(t, "riyadh-1")
	first := env.epochs[relay.ID]
	hello := RelayHello{URL: testRelayURL, Fingerprint: testRelayFP, Version: "0.2.0"}
	second, err := env.relays.Attach(ctx, relay.ID, hello)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("two attachments share an epoch")
	}
	if env.relays.Current(relay.ID, first) || !env.relays.Current(relay.ID, second) {
		t.Errorf("current: first=%v second=%v", env.relays.Current(relay.ID, first), env.relays.Current(relay.ID, second))
	}
	gen := env.generation(t)
	if err := env.relays.Detach(ctx, relay.ID, first); err != nil {
		t.Fatal(err)
	}
	if on, _ := env.relays.Online(ctx); len(on) != 1 || env.generation(t) != gen {
		t.Errorf("the replaced stream's end took the relay offline: online %d, generation %d (was %d)", len(on), env.generation(t), gen)
	}
	if err := env.relays.Detach(ctx, relay.ID, second); err != nil {
		t.Fatal(err)
	}
	if on, _ := env.relays.Online(ctx); len(on) != 0 || env.generation(t) != gen+1 {
		t.Errorf("after the current stream ended: online %d, generation %d", len(on), env.generation(t))
	}
	// A heartbeat still in flight from the replaced stream brings
	// nothing back.
	if err := env.relays.Heartbeat(ctx, relay.ID, first, RelayStats{Sessions: 9}); !errors.Is(err, ErrNotFound) {
		t.Errorf("heartbeat of a replaced stream: %v", err)
	}
	if on, _ := env.relays.Online(ctx); len(on) != 0 || env.generation(t) != gen+1 {
		t.Errorf("a stale heartbeat changed liveness: online %d, generation %d", len(on), env.generation(t))
	}
	// A deleted relay has no current attachment.
	if _, err := env.relays.Delete(ctx, env.admin, "riyadh-1"); err != nil {
		t.Fatal(err)
	}
	if env.relays.Current(relay.ID, second) {
		t.Error("an attachment of a deleted relay still counts as current")
	}
}

func TestRelaySessionPeer(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	alice := env.peer(t, "alice")
	p, err := env.relays.SessionPeer(ctx, alice.ID)
	if err != nil || p.PublicKey != alice.PublicKey {
		t.Fatalf("session peer: %+v %v", p, err)
	}
	newKey := newPubKey(t)
	if _, err := env.registry.RotateKey(ctx, alice.ID, newKey, nil); err != nil {
		t.Fatal(err)
	}
	if p, err := env.relays.SessionPeer(ctx, alice.ID); err != nil || p.PublicKey != newKey {
		t.Errorf("after rotation: %+v %v", p, err)
	}
	if err := env.registry.Delete(ctx, env.admin, alice.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := env.relays.SessionPeer(ctx, alice.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}

// TestNetMapRelays: the online relay nodes and a ticket for each are in
// the netmap of a device that can use them, and in no other.
func TestNetMapRelays(t *testing.T) {
	env := newRelayEnv(t)
	ctx := context.Background()
	riyadh := env.online(t, "riyadh-1")
	berlin := env.online(t, "berlin-1")
	env.register(t, "offline-1")
	a, b := env.enrolled(t, "alice", false), env.enrolled(t, "bob", false)
	builder := NewNetMapBuilder(env.st, OwnerVisibility{}, nil, nil,
		HubConfig{Overlay: netip.MustParsePrefix("100.64.0.0/10")}, func() int64 { return 1 }).WithRelayTickets(env.relays)

	// Nobody said they can use relay nodes yet.
	for _, p := range []store.Peer{a, b} {
		nm, err := builder.Build(ctx, p.ID)
		if err != nil || len(nm.Relays) != 0 {
			t.Fatalf("%s before the capability: %d relays, %v", p.Name, len(nm.Relays), err)
		}
	}
	if changed, err := env.registry.SetRelayCapable(ctx, a.ID, true); err != nil || !changed {
		t.Fatalf("SetRelayCapable: %v %v", changed, err)
	}
	nm, err := builder.Build(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Sorted by name, the offline relay left out.
	if len(nm.Relays) != 2 || nm.Relays[0].Relay.ID != berlin.ID || nm.Relays[1].Relay.ID != riyadh.ID {
		t.Fatalf("alice's relays: %+v", nm.Relays)
	}
	for _, g := range nm.Relays {
		if len(g.Ticket) != TicketLen || !g.Expires.After(env.clk.Now()) {
			t.Errorf("grant for %s: %d ticket bytes, expires %s", g.Relay.Name, len(g.Ticket), g.Expires)
		}
		if p, err := env.relays.Admit(ctx, g.Relay.ID, g.Ticket); err != nil || p.ID != a.ID {
			t.Errorf("ticket for %s admits %q, %v", g.Relay.Name, p.ID, err)
		}
	}
	// The same tickets again in the next netmap, and none in bob's: he
	// sees alice, not her credentials.
	again, err := builder.Build(ctx, a.ID)
	if err != nil || len(again.Relays) != 2 || !bytes.Equal(again.Relays[0].Ticket, nm.Relays[0].Ticket) {
		t.Errorf("second build issued other tickets: %v", err)
	}
	if other, err := builder.Build(ctx, b.ID); err != nil || len(other.Relays) != 0 || len(other.Peers) != 1 {
		t.Errorf("bob's netmap: %d relays, %d peers, %v", len(other.Relays), len(other.Peers), err)
	}

	// A client that stops saying it can use relay nodes (a downgrade)
	// gets none and its tickets stop working.
	gen := env.generation(t)
	if changed, err := env.registry.SetRelayCapable(ctx, a.ID, false); err != nil || !changed {
		t.Fatalf("clearing: %v %v", changed, err)
	}
	if after, err := builder.Build(ctx, a.ID); err != nil || len(after.Relays) != 0 {
		t.Errorf("after the downgrade: %d relays, %v", len(after.Relays), err)
	}
	for _, g := range nm.Relays {
		if _, err := env.relays.Admit(ctx, g.Relay.ID, g.Ticket); !errors.Is(err, ErrForbidden) {
			t.Errorf("old ticket for %s after the downgrade: %v", g.Relay.Name, err)
		}
	}
	// Nor does a ticket issued after it, as a netmap build that read
	// the flag just before the downgrade would get.
	late, err := env.relays.Tickets(ctx, a.ID)
	if err != nil || len(late) != 2 {
		t.Fatalf("tickets: %d %v", len(late), err)
	}
	if _, err := env.relays.Admit(ctx, late[0].Relay.ID, late[0].Ticket); !errors.Is(err, ErrForbidden) {
		t.Errorf("a ticket issued after the downgrade: %v", err)
	}
	if env.generation(t) != gen {
		t.Errorf("the capability moved the generation: %d, was %d", env.generation(t), gen)
	}
	if _, err := env.registry.SetRelayCapable(ctx, "p_missing", true); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown peer: %v", err)
	}

	// Asked for at enrolment, it is there from the first netmap.
	res, err := env.enroller.Enroll(ctx, EnrollRequest{Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t),
		Hostname: "carol", OS: "linux", Arch: "amd64", ClientVersion: "0.2.0", RelayNodes: true})
	if err != nil {
		t.Fatal(err)
	}
	if first, err := builder.Build(ctx, res.Peer.ID); err != nil || len(first.Relays) != 2 {
		t.Errorf("enrolled with relay_nodes: %d relays, %v", len(first.Relays), err)
	}
}
