# Thawr — Architecture

This document is normative. Implementation sessions follow it; changes go
through an ADR in `docs/adr/`.

## 1. Components

One binary, three roles:

| Role | Command | Runs where | Responsibilities |
|---|---|---|---|
| Server | `thawr server --config server.yaml` | One host with a public IP or forwarded ports | Peer registry, enrollment, key distribution, policy evaluation, STUN, relay, WireGuard hub for mobile peers, admin REST API and UI |
| Client | `thawr client up|down|status` | Every laptop, server, VM | Generates and holds the node key, configures the local WireGuard interface, discovers endpoints, probes direct paths, falls back to relay, enforces the receiver-side port filter |
| Admin | `thawr admin ...` | On the server host (Unix socket) or remotely (REST with a session) | Users, tokens, peers, policy check and reload, mobile QR export |

`thawr server install` and `thawr client install` register the same
binary with the host's service manager (systemd, launchd, Windows SCM)
so both roles start at boot and restart on failure; `uninstall`
reverses it. `thawr version` reports version, toolchain, platform and
commit; releases are built reproducibly by CI from tags with published
checksums (spec 009).

Network ports on the server, all configurable:

| Port | Protocol | Purpose |
|---|---|---|
| 443 | TCP, TLS | gRPC (clients), REST + admin UI (browsers), relay (HTTP Upgrade `thawr-relay/1`) |
| 3478, 3479 | UDP | STUN. Two ports so a client can detect endpoint-dependent (symmetric) NAT |
| 51820 | UDP | Server's own WireGuard interface (the hub). Used by mobile peers and by any peer as a stable direct endpoint to the server |

```mermaid
flowchart LR
  subgraph Server host
    S[thawr server]
    DB[(SQLite)]
    HUB[WireGuard hub thawr0]
    S --- DB
    S --- HUB
  end
  subgraph Laptop
    C1[thawr client] --- W1[WireGuard]
  end
  subgraph Home server behind NAT
    C2[thawr client] --- W2[WireGuard]
  end
  P[Phone with WireGuard app]
  A[Admin browser / CLI]

  C1 -- gRPC TLS 443 --> S
  C2 -- gRPC TLS 443 --> S
  C1 -- STUN UDP 3478 --> S
  C2 -- STUN UDP 3478 --> S
  W1 <-. direct UDP, when NAT allows .-> W2
  C1 -- relay TLS 443 --> S
  C2 -- relay TLS 443 --> S
  P -- WireGuard UDP 51820 --> HUB
  A -- REST TLS 443 / unix socket --> S
```

## 2. Packages

Dependencies point downward only. `cmd/thawr` parses flags and hands
the config to `internal/server`, which wires everything; nothing below
`cmd` imports a sibling that is not listed here.

```mermaid
flowchart TD
  CMD[cmd/thawr] --> SRV[internal/server]
  CMD --> CFG[internal/config]
  SRV --> API[internal/api]
  SRV --> RELAY[internal/relay]
  SRV --> WG[internal/wg]
  SRV --> WEB[web]
  SRV --> STORE[internal/store]
  SRV --> STUN[internal/stun]
  WG --> STUN
  API --> CTRL[internal/control]
  API --> RELAY
  CTRL --> STORE
  RELAY --> CTRL
```

| Package | Single responsibility | Exposes | Depends on |
|---|---|---|---|
| `internal/config` | Load one YAML file, apply defaults, validate | `Load(path) (*Config, error)`, `Config` struct, `Default()` | stdlib, yaml |
| `internal/store` | Persist peers, users, tokens, policy generation and the audit log in SQLite; run migrations | `Open(dsn) (*Store, error)`, `Store.Peers()`, `Store.Users()`, `Store.Tokens()`, `Store.Meta()`, `Store.Audit()`, each a small interface with ctx-first methods | `modernc.org/sqlite` |
| `internal/control` | Everything that decides: enrollment, registry, key distribution (netmap), policy compilation, endpoint tracking, IP allocation, audit recording, the network lock record and peer signatures | `Enroller`, `Registry`, `Policy` (parse + compile), `NetMapBuilder`, `EndpointTable`, `Allocator`, `Auditor`, `LockService` | `internal/store`, `internal/lock` |
| `internal/lock` | Network lock records (spec 012), pure: Ed25519 keys and signatures (`crypto/ed25519`), the canonical bytes of a peer record `(id, name, key)` and of a lock record `(generation, disabled, signers)`, and the rule for accepting a successor record | `GenerateKey`, `Sign`, `Verify`, `PeerRecord.Bytes`, `Record.Bytes`, `Accept` | none |
| `internal/wg` | Talk to a WireGuard device without knowing about Thawr | `Device` interface (`Configure` diffs peers in place, `SetPeer`, `RemovePeer`, `Stats`), `Open(ctx, Options)` (kernel via wgctrl on Linux, else wireguard-go configured through its in-process IPC API, no UAPI socket), `STUNCapable` (the userspace device sends STUN from its own socket), `Filter` interface (spec 006), `wgtest.Fake` | `wgctrl`, `wireguard-go`, netlink / nftables, `internal/stun` |
| `internal/stun` | STUN binding codec (copied from Tailscale), `Discover` client with symmetric-NAT detection, rate-limited `Serve` | `Request`, `ParseResponse`, `Transport`, `Discover`, `Serve` | stdlib |
| `internal/control/path` | Candidate ordering both sides compute identically and the per-peer path state machine (pure, clock and stats injected) | `Order`, `Machine.Step` | `internal/control` types |
| `internal/relay` | Forward opaque packets between authenticated peers; local UDP proxy on the client | `Server`, `Client`, frame codec | `internal/control` (for auth + visibility check via a small interface) |
| `internal/api` | gRPC service and REST handlers; translate wire types to `control` calls; no business logic | `NewGRPC(deps)`, `NewREST(deps)`, `Combine` (one listener for both), protobuf under `internal/api/proto` generated with buf via `make proto` | `internal/control`, `internal/relay` |
| `internal/client` | Device side independent of the CLI: state directory (node key, lock key, enrollment state, netmap cache, key pins and the pinned lock record), TLS fingerprint pinning, the Enroll call, the sync daemon with endpoint discovery and the path prober, key pinning with hold-until-trusted, the network lock (hold unsigned, sign from the daemon), and its local socket API | `Enroll(ctx, Options)`, `NewDaemon(DaemonOptions)`, `Daemon.Run`, `Daemon.Ping`, `Daemon.Trust`, `Daemon.LockInit`, `Daemon.LockSign`, `BuildConfig`, `LoadPins`, `NewLocalClient`, `LoadState`, `Forget` | `internal/api/proto`, `internal/wg`, `internal/stun`, `internal/control/path`, `internal/lock` |
| `internal/server` | Compose the server: data dir, store, server key, TLS, hub interface, policy, listeners; startup order, readiness, reload, shutdown | `New(cfg, Deps)`, `Run(ctx, reload)`, `Check()`, `Status(ctx)` | `internal/config`, `internal/store`, `internal/wg`, `internal/control`, `internal/api`, `web` |
| `web` | Static admin UI, embedded | `embed.FS` | nothing |
| `internal/svc` | Register the binary as a system service: render systemd units and launchd plists, drive `systemctl`/`launchctl` through an injected runner, create Windows services via x/sys | `New(Options) (Manager, error)`, `Manager.Install/Start/Stop/Uninstall/Status/Logs`, `RenderSystemdUnit`, `RenderLaunchdPlist` | `golang.org/x/sys/windows/svc` |
| `internal/dns` | Serve the `thawr` zone from an injected `Source` (A and PTR, NXDOMAIN, REFUSED or forwarding outside the zone), and route the zone to the resolver per platform | `NewServer(Options)`, `Server.Handle/Serve`, `Listen`, `Source`, `Registrar`, `NewRegistrar(RegistrarOptions)` | `golang.org/x/net/dns/dnsmessage` |
| `cmd/thawr` | Flags, config, dependency wiring, signal handling, install commands | `main` | all of the above |

Interfaces are declared in the consuming package. `control` declares the
storage interfaces it needs; `store` satisfies them. `api` declares what
it needs from `control`; tests use fakes.

## 3. Identity model

Every entity that can hold a WireGuard key is a **peer**. A peer has:

| Field | Meaning |
|---|---|
| `id` | 128-bit random, hex |
| `name` | Unique, DNS-label safe, e.g. `alice-laptop`; derived from hostname at enrollment, admin can rename |
| `kind` | `human`, `server`, `agent`. Informational in v1; phase 2 attaches workload identity semantics without changing the schema |
| `mode` | `agent` (runs `thawr client`, participates in NAT traversal) or `static` (plain WireGuard config, e.g. a phone; routed via the hub) |
| `owner` | Optional reference to a user. Servers and agents may be unowned and are addressed by tags |
| `tags` | Set of `tag:name`. Policy addresses peers by owner, group, or tag |
| `public_key` | WireGuard public key. Private key never leaves the device for `agent` peers |
| `ipv4` | Overlay address, `/32`, allocated by the server from `overlay.cidr` |
| `node_secret_hash` | SHA-256 of the bearer secret an `agent` peer uses on the control channel |
| `last_seen_at`, `created_at`, `expires_at` | Lifecycle |

**Users** are local accounts with a name, role (`admin`, `member`), and
an argon2id password hash. Users log into the admin UI and own peers.
Members can list their own peers and create tokens for themselves;
admins can do everything. OIDC, when enabled, maps an external subject to
a local user record. The policy engine only ever sees users, groups and
tags, so the identity source is irrelevant to it.

**Enrollment tokens** are single-use secrets created by an admin (or a
member for their own peers). A token pins: owner, kind, tags, expiry.

## 4. Data flows

### 4.1 Server bootstrap

On first start with `public_addr: vpn.example.com` the server creates
`data_dir` (default `/var/lib/thawr`), opens `thawr.db`, runs migrations,
generates its WireGuard key (`server.key`, 0600), generates a self-signed
TLS certificate valid 10 years with SAN = public host
(`tls/cert.pem`, `tls/key.pem`), brings up `thawr0` with `100.64.0.1/10`,
starts STUN, relay, gRPC, REST, and prints the TLS fingerprint. Subsequent
starts reuse everything. Spec 001.

### 4.2 Enrollment

```mermaid
sequenceDiagram
  participant Adm as Admin
  participant S as Server
  participant C as New client
  Adm->>S: thawr admin token create --owner alice --kind human --expires 1h
  S-->>Adm: token thawr_xxx (shown once) + join command incl. server URL and TLS fingerprint
  Adm->>C: paste join command
  C->>C: generate WireGuard keypair, store node.key 0600
  C->>S: gRPC Enroll(token, public_key, hostname, os, version) over TLS (fingerprint pinned)
  S->>S: hash token, lookup, check expiry and unused, mark used
  S->>S: allocate ipv4, create peer, generate node secret
  S-->>C: EnrollResponse(peer_id, ipv4, node_secret, overlay cidr, server hub key + endpoint)
  C->>C: persist state.json 0600 (server, fingerprint, peer_id, node_secret)
  C->>S: Sync stream (authorization: Bearer node_secret)
```

Token secret: 32 bytes from `crypto/rand`, base64url, prefixed
`thawr_`. The server stores only SHA-256(secret). Default expiry 1 hour,
maximum 30 days. A used or expired token is rejected with the same error
code. Spec 002.

### 4.3 Key distribution (netmap sync)

The server holds a **netmap generation**: a persisted counter bumped by
every change to peers or policy, mirrored by an in-memory sequence in
the presence hub that also advances on endpoint and presence changes
and is what netmaps and the status endpoint carry. Each client holds
one server-streaming gRPC call `Sync`. On connect the server always
sends a full map (the client's reported generation is informational);
on every change affecting the peer, coalesced over 200 ms, and every
30 s as a keepalive, it sends the full map again. It computes that
peer's view:

- the peers it may talk to (policy says A→B or B→A allows at least one
  port), each with public key, ipv4, current endpoint candidates, online
  flag
- the hub as a peer with AllowedIPs covering every `static` peer's address
- the receiver-side filter rules for this peer (source ipv4 → allowed
  proto/ports)
- the signed lock record, if any, and per peer (the hub and the
  receiver itself included) the signatures over its current record
  (spec 012)

With the network lock on (spec 012) the client runs the lock check
before the pins: the record the server offers is reconciled with the
one pinned in `pins.json` (the first is pinned as offered; a later one
must carry a higher generation and a signature by a key of the pinned
set, else it is refused and `status` reports why; no record at all
keeps the pin, so only a signed `disabled` record turns the lock off).
Then every agent peer and the hub must carry a signature by a signer of
the pinned record over `(id, name, key)`; the rest are **held** with
reason `unsigned` and `trust` cannot release them. Signed entries are
accepted into the pins, so a signed rotation or a signed new peer
passes the pin check below without a trust step.

The client then checks every netmap against its pins (spec 011): the
hub key and each agent peer's `(id, key)` under the peer's name, stored
in `pins.json`. A first-seen name is pinned, a known id under a new name
keeps its pin (the old name stays pinned, so a later peer taking that
name is held), and a known name whose id or key differs is **held**:
removed from the netmap the client applies, so it gets no WireGuard
peer, no filter rule, no `<name>.thawr` and no path probing until
`thawr client trust <name>` (local API `POST /trust/{name}`) accepts
the offered key. A changed hub key holds the hub the same way; direct
mesh paths and the TLS-pinned control connection are unaffected. The
client then turns what passed into the complete WireGuard configuration
and applies it (adapters diff peers in place, so WireGuard keeps
sessions for unchanged keys), caches the netmap as received on disk (held
entries are derived again from the pins on the next start), and
installs the filter (spec 006). A peer is online while its `Sync` stream is open and for 90 s
after it drops. Removing a peer on the server propagates to every
client within 5 seconds and closes that peer's stream. The server's
hub interface carries every registered peer as a WireGuard peer, so
clients' keepalives toward the hub keep a tunnel to the server open.
Spec 003.

```mermaid
sequenceDiagram
  participant C as Client
  participant S as Server
  participant W as WireGuard
  C->>S: Sync(current_generation)
  S-->>C: NetMap(gen=42, peers, filter)
  C->>W: set peers, allowed IPs, endpoints
  Note over S: admin deletes peer X (gen=43)
  S-->>C: NetMap(gen=43)
  C->>W: remove peer X
  C->>S: ReportEndpoints(local, stun) every 60s or on change
```

### 4.4 Direct connectivity

Clients learn their endpoints: local interface addresses (outside the
overlay) with the WireGuard listen port, plus the server-reflexive
address from STUN on both server STUN ports, whose `host:port` the
netmap carries. If the two reflexive ports differ, the NAT is
endpoint-dependent and the client reports `symmetric: true`. With
`wireguard-go` the STUN request leaves from the WireGuard socket itself
(a `conn.Bind` wrapper filters the responses out of the receive path),
so the mapping is exact. The kernel module's UDP socket cannot be
shared, so there STUN runs from an ephemeral socket: it yields the
public IP and the symmetric verdict, the reflexive candidate assumes a
port-preserving NAT, and the server adds the exact mapping it observes
on the hub interface (the source address of the peer's WireGuard
packets) as a further reflexive candidate. Reports go out on connect,
when the local address set changes, and otherwise every 60 s.

Every netmap peer starts `idle`: its WireGuard endpoint points at a
loopback sink socket the daemon owns, which never transmits. As soon as
traffic for the peer is queued, WireGuard sends its handshake initiation
to the sink and the daemon knows there is traffic intent (`thawr client
ping <peer>` sets it explicitly). To reach peer B, client A orders B's
candidates (local addresses sharing a /24 with one of A's, other local,
reflexive, hub-stable; ties by address; reflexive skipped when both are
symmetric), removes and re-adds B with the first candidate as endpoint
(the re-add resets WireGuard's 5 s handshake retry timer) and sends one
UDP datagram to B's overlay address through the interface, which makes
WireGuard initiate a handshake there. B does the same toward A with the
identical ordering, so both sides punch holes simultaneously; a
handshake B initiates first is accepted too, and WireGuard's roaming
moves the endpoint to wherever authenticated packets come from. A
candidate is accepted when `last_handshake_time` advances within 2
seconds. If the list is exhausted (10 seconds at most) the path is
`relay` (§4.5), re-probed from there as described below. A
`direct` path with queued traffic but no handshake for 3 minutes is
re-probed. Path states are reported to the server (`ReportPath`) and
shown in the admin UI. No userspace packet multiplexing: the kernel or
`wireguard-go` device is always the one sending. Spec 004.

### 4.5 Relay fallback

```mermaid
sequenceDiagram
  participant WA as WireGuard A
  participant PA as relay proxy A (127.0.0.1:pA)
  participant R as Relay (server)
  participant PB as relay proxy B (127.0.0.1:pB)
  participant WB as WireGuard B
  WA->>PA: UDP WireGuard packet (endpoint = 127.0.0.1:pA)
  PA->>R: frame{dst=B pubkey, payload}
  R->>R: A and B authenticated, mutually visible?
  R->>PB: frame{src=A pubkey, payload}
  PB->>WB: UDP to WireGuard listen port
```

Each client keeps one TLS connection to `/relay` (HTTP/1.1 Upgrade
`thawr-relay/1`, authenticated with the node secret before anything
past the headers is read), opened when the first peer needs the relay
and closed after five minutes without relayed peers; it reconnects with
the same jittered backoff as the sync stream and answers a 30 s ping.
For every relayed peer it opens one local UDP socket on `127.0.0.1` and
points the WireGuard endpoint at it: datagrams WireGuard sends there
become `SEND` frames, `RECV` frames are written from that socket to the
WireGuard port. Frames are `type(1) | key(32) | length(2) | payload`,
at most 1500 payload bytes; only payloads starting with a WireGuard
message type (1–4) are forwarded, on both ends. The relay forwards only
between peers that are mutually visible (`control.KeyVisibility`,
cached per netmap generation), answers `PEER_GONE` at most once per
second per pair, closes a session after ten visibility violations per
minute, keeps a 256-frame queue per session (drop on overflow) and an
optional per-peer byte rate (`relay.max_bytes_per_second`); the
counters appear in `/api/v1/status`. A newer connection for the same
key replaces the older one, and a deleted peer's session is closed with
the next registry change. The relay never sees anything but WireGuard
ciphertext and never logs payload bytes.

The path machine ends an exhausted candidate list in `relay` instead of
`unreachable`. From the relay it retries one candidate every 60 s (the
next in turn), returning to the relay when the 2 s window passes, so a
failed retry costs at most one window of loss; a candidate change (new
netmap on both sides at once) starts a full simultaneous round, which
is what upgrades a relayed pair to `direct` after a network change. A
handshake arriving from a public address while relayed also upgrades
the path (roaming). Spec 005.

### 4.6 Policy evaluation

The policy file is YAML with `groups`, `tagOwners`, and `acls`. Rules
have `action` (only `accept`), `src` selectors, `dst` selectors with
ports, optional `proto`. Selectors: `*`, `user:name`, `group:name`,
`tag:name`, `peer:name`, CIDR. Default deny.

Compilation produces, for every ordered pair (src peer, dst peer), the
set of allowed (proto, port ranges). Two peers are **visible** to each
other when either direction is non-empty. Enforcement:

1. Key distribution: a client only receives keys of visible peers. This
   alone stops any traffic between peers with no relationship.
2. Receiver-side filter: the destination client drops packets from source
   overlay addresses not permitted for that proto/port, installed from
   `netmap.filter` on every map. On Linux with kernel WireGuard this is
   the nftables table `inet thawr` with a drop-policy chain on the input
   hook: `iifname != thawr0 accept`, `ct state established,related
   accept`, ICMP echo from the visible set, one rule per policy entry,
   a counting drop; every change rebuilds the table in one batch. With
   `wireguard-go` it is a userspace filter between the device and the
   TUN: outbound packets record flows (UDP 120 s idle, TCP an hour or
   30 s after FIN/RST, ICMP echo by identifier), inbound packets must
   answer a flow, be an ICMP diagnostic from a visible peer or match a
   rule. Drops are counted and shown in `client status`.
3. Hub-side filter: the server applies the same rules on the forward
   hook of its hub interface for `static` peers (spec 008).

Compilation resolves every rule to source and destination bitsets over
the peer list (`self` is checked per pair by owner) and answers
`Allowed`, `Visible`, `FilterFor` and `MayUseTag`; the server caches it
per (policy hash, persisted generation). Validation against the
registry treats unknown users and groups as errors and unknown tags and
peers as warnings. `tagOwners` is enforced when members create tokens.
The server reloads the policy on `SIGHUP`, on `thawr admin policy
reload` and on `POST /api/v1/policy/reload`; an invalid file never
replaces the running policy and the errors name the rule index and
field; a successful reload bumps the generation so every client gets a
new map and filter within seconds. `thawr admin policy check file.yaml`
validates against the running server without installing; `show` prints
the effective policy with its hash. Spec 006.

### 4.7 Mobile (static) peers

`thawr admin peer add-mobile --owner alice --name alice-phone` (or
`POST /peers/mobile`, or the admin UI) asks `Registry.CreateStatic` to
generate a WireGuard keypair in server memory, store the public key as
a `static` peer with the next free overlay address and no node secret,
and bump the generation. The REST layer renders a standard WireGuard
`.conf` (`Endpoint = public_addr:51820`, `AllowedIPs = <overlay
cidr>`, keepalive 25 s) and a QR code (half blocks in the terminal,
SVG in the UI), returns them once and zeroes the key. Admins may
create for any owner; members only for themselves and only with tags
`tagOwners` grants them.

The generation bump makes `followRegistry` add the phone to the hub
interface (`AllowedIPs = <ip>/32`) and `installHubFilter` install, on
the forward hook, every policy rule whose source or destination is a
static peer (the hub forwards nothing else); the hub host forwards
between the interface and itself (Linux: `conf/<iface>/forwarding`,
macOS: `net.inet.ip.forwarding`, both set at startup; on Linux hosts
whose forward chain drops by default, as Docker's does, the hub inserts
an accept rule for its own interface into that chain and removes it on
shutdown). A host that
runs the server is itself a peer (the hub) and cannot also run a
client: both would claim the overlay route; `client install` refuses. Agent peers receive the phone as a `via_hub` netmap
entry: no WireGuard peer of their own, its /32 routed to the hub, its
address in their filter's visible set, and `via hub` in `client
status`. Presence for a phone is its hub handshake: `observeOnce`
records it as `last_seen_at` and the peer counts as online while the
handshake is under three minutes old. Deleting the peer removes it from
the hub and every netmap on the next generation. The threat model
records that the server sees plaintext for static peers only (T4);
the CLI and the UI say so wherever the config is shown. Spec 008.

### 4.8 Names

Every peer is `<name>.thawr`; `hub.thawr` is the server's hub address.
Peer names are unique DNS labels since enrollment (spec 002), so the
zone needs no extra data: the client's `Daemon` implements
`dns.Source` over its current netmap (self, hub, visible peers) and
binds `<self ip>:53` UDP and TCP after the interface has its address.
Once the first netmap is applied it asks the platform registrar
(`internal/dns`) to route the zone there: `resolvectl dns/domain
~thawr/default-route false` where systemd-resolved runs, a
`# thawr begin/end` block in `/etc/hosts` otherwise (rewritten
atomically on every netmap), `/etc/resolver/thawr` on macOS, an NRPT
rule on Windows. Registration happens only once the resolver is bound,
so the OS is never pointed at a void; the daemon unregisters when `Run`
returns, on any path, and unregisters before registering, so what a
crashed instance left behind is cleared at the next start. `--dns
serve` skips registration, `--dns off` skips everything; a bind failure
is shown in `client status`, never fatal. The client resolver answers
only the local host (its own overlay address and loopback): a peer the
policy lets reach port 53 gets nothing, so a device's netmap is not
disclosed through names. Answers carry a 30 s TTL; names outside the
zone are REFUSED, since the OS only routes `.thawr` to the client
resolver.

The server binds the same resolver on the hub address
(`dns.enabled`, default true) with a `Source` over the peer registry,
cached per hub generation, that answers a requesting overlay address
only with peers the policy makes visible to it (the same `Visibility`
that decides key distribution) plus the hub. The phone config carries
`DNS = <hub ip>, thawr`; because the WireGuard app then sends every
query through the tunnel, the hub resolver forwards names outside the
zone to `dns.upstream` or, when empty, the nameservers of the host's
`/etc/resolv.conf` read at start, over the transport the query arrived
on, first answer wins, no cache. Both resolvers drop queries from
outside the overlay and listen on overlay addresses only, so neither is
reachable from the internet. Spec 010.

### 4.9 Routes: subnet routers and exit nodes

A peer that runs `client up --advertise-routes 10.1.0.0/24` or
`--advertise-exit-node` (the prefix `0.0.0.0/0`) reports its complete
advertised set through `AdvertiseRoutes` at every connect; the server
stores the prefixes unapproved in `peer_routes` and audits every
change. Nothing moves until an admin approves a prefix (`thawr admin
peer routes approve <name> <prefix>`) and the policy grants it: a `dst`
CIDR outside the overlay is a subnet route, `internet` is any approved
exit node, and the ports apply to the destination behind the router.
The compiler turns such a rule into forward rules per source peer and
router (the rule's own CIDR, not the advertised one) and makes the
router visible to the source without opening a port on the router
itself. The source's netmap carries the prefix as an extra `AllowedIP`
of the router (one router per prefix; the lowest peer id wins when
several advertise it) or the `exit_node` flag; the router's netmap
carries the forward rules and its own advertisements with their
approval.

The client installs an OS route through `thawr0` for every extra
`AllowedIP` and removes it when it leaves the netmap or the daemon
stops. `thawr client exit-node <name>` adds `0.0.0.0/0` to that peer
and, on Linux, marks the tunnel's own packets with a fwmark and sends
everything else to a routing table whose only route is the default
through `thawr0` (the wg-quick scheme), so the WireGuard endpoint and
the control connection stay outside the tunnel; the choice is
persisted and shown as `active` or `unavailable` (peer held, offline
or no longer approved: traffic then leaves the normal way, no kill
switch). A router enables `ip_forward` while it runs and extends its
`inet thawr` table with a forward chain (policy drop; established
flows and the forward rules from the netmap pass) and a nat chain
that masquerades overlay sources toward the prefixes it advertises.
The router takes the prefixes it forwards from its own state, never
from the netmap, so a server that invents a route on a peer sends
traffic into a drop rule. With `wireguard-go` on Linux the userspace
filter passes forwarded packets whose destination a forward rule
covers and the same nftables chains handle forwarding and nat.
Routers and exit-node use need Linux in this release; the flags and
`exit-node` refuse elsewhere, plain subnet routes are installed on
every platform. Spec 013.

## 5. Wire interfaces

### gRPC `thawr.v1.Control`

| RPC | Auth | Purpose |
|---|---|---|
| `Enroll(EnrollRequest) EnrollResponse` | enrollment token | Register a new agent peer |
| `Sync(SyncRequest) stream NetMap` | node secret | Long-lived netmap push |
| `ReportEndpoints(EndpointReport) Empty` | node secret | Candidates + NAT type |
| `ReportPath(PathReport) Empty` | node secret | direct/relay state per peer (for status and admin UI) |
| `RotateKey(RotateKeyRequest) RotateKeyResponse` | node secret | Replace the WireGuard key; old key valid until next generation is acknowledged; a signer may attach its signature over the new key, stored in the same transaction |
| `Leave(Empty) Empty` | node secret | Peer removes itself |
| `SetLock(SetLockRequest) Empty` | node secret | Install a signed lock record (the first one only from a device an admin owns, later ones per `lock.Accept`), optionally with the signatures that go with it |
| `SignPeer(SignPeerRequest) Empty` | node secret, signer | Store a signature over a peer's (or the hub's) current record |
| `ListLockPeers(Empty) LockPeers` | node secret, signer | Every peer with its signed state and reported lock key; the one RPC that shows a peer the whole registry, and only to a signer the record names |
| `AdvertiseRoutes(AdvertiseRoutesRequest) AdvertisedRoutes` | node secret | Replace the caller's advertised prefixes; the reply carries their approval (spec 013) |

Node secret travels as gRPC metadata `authorization: Bearer <secret>`.
Every message carries `client_version`; the server rejects versions older
than its `min_client_version`. `SyncRequest.lock_key` reports the
device's lock public key, if it has one, so a signer can add it.

### REST `/api/v1` (admin)

`POST /login`, `POST /logout`, `GET /me`, `GET /status`, `GET|POST /users`,
`GET|POST /tokens`, `DELETE /tokens/{id}`, `GET /peers`,
`GET|PATCH|DELETE /peers/{name}`, `POST /peers/mobile`, `GET /policy`,
`POST /policy/check`, `POST /policy/reload`, `GET /audit` (admins;
`since`, `before_id`, `action`, `actor`, `limit`), `GET /lock` (the
signer set and the unsigned peers; peer views carry `signed` while the
lock is on), `GET /peers/{name}/routes` and `PUT
/peers/{name}/routes/{prefix}` with `{"approved": bool}` (admins; the
peer detail lists `routes`). JSON bodies. Browser
sessions are in memory (12 h) behind one `HttpOnly`, `Secure`,
`SameSite=Strict` cookie; the session's CSRF token is returned by
`/login` and `/me` and must be sent as `X-CSRF-Token` on mutating calls.
The Unix socket exposes the same API without login as the local admin;
access is filesystem permission (`root` and group `thawr`).

### Client local API

`thawr client status` talks to the running daemon over
`/var/run/thawr/client.sock` (a Unix socket on every platform; Windows
supports `AF_UNIX`; mode 0660, group `thawr` where that group exists)
with a tiny JSON-over-HTTP API: `GET /status`, `POST /down`,
`POST /rotate-key`, `POST /trust/{name}` (accept a held key; `all` for
every held one, `hub` for the hub), `POST /ping/{name}` (mark
traffic intent, probe, answer with the settled path), and the network
lock (spec 012): `POST /lock/init`, `POST /lock/sign/{name}` (`all`,
`hub`), `POST /lock/key`, `POST /lock/add-signer/{name}?key=<full lock public key read on
that device>`, `POST /lock/disable`, each
answering with the generation and the fingerprints it signed.

`GET /status` returns the document described by `docs/status.schema.json`:
`version`, `self`, `server`, `wireguard`, `nat`, `relay`, `filter`,
`dns`, `hub`, `peers[]`, `held[]`, `lock`, `retrieved_at`. Fields are only ever
added. `held[]{name, ipv4, kind, owner, pinned_key, offered_key, since,
reason}` lists the entries held out of the tunnel (`reason`
`key_changed` or `unsigned`); each also appears in `peers` (or `hub`)
with `path` `key_changed` or `unsigned`. `lock{enabled, signer,
has_key, generation, signers[], rejected, self_signed}` is the network
lock as the device sees it.
`dns{listen, state, method, names, error}` describes the client's
resolver (`state` `serving` or `error`; `method` `resolved`, `hosts`,
`resolver-file`, `nrpt` or `none`) and is absent with `--dns off`.
`server.state` is `connected`, `reconnecting` (no netmap at all) or
`cached` (running on the last netmap while the server is unreachable),
with `attempt`, `next_retry_at` and `unreachable_since` alongside;
`server.version` is what the last netmap said about the server
(`NetMap.server_version`), and the CLI adds `client update available`
when its MAJOR.MINOR is ahead of the client's. That is the only update
signal Thawr has; it never contacts anything but the user's server.
`nat.type` is derived from STUN: `symmetric`, `none` (the mapped address
is one of ours), `cone`, or `unknown` when STUN never answered. A peer's
`path` is the prober's state (`idle`, `probing`, `direct`, `relay`,
`unreachable`), `offline` when the server reports the peer offline and
no path is in use, `hub` for peers reached through the hub,
`key_changed` for a peer held until trusted, or `unsigned` for one the
lock has not signed;
`filter.dropped_5m` is a sampled five-minute window over the device's
drop counter. The CLI is a thin renderer of that document: the table by
default, `--json` verbatim, `--watch` redrawn every 2 s. Exit codes:
0 connected, 1 running but the server is unreachable, 2 usage error,
3 daemon not running. `client ping` combines `POST /ping/{name}` with
the system `ping` and reports path changes it observes in between.

## 6. Storage

SQLite, WAL mode, single writer. Tables: `users`, `peers`,
`enrollment_tokens`, `meta` (netmap generation, schema version, server
key fingerprint, the signed lock record as JSON under `lock_record`),
`audit_log` (`at`, `actor`, `actor_role`, `action`, `target`, `details`
JSON; appended inside the mutation's transaction, pruned after
`audit.retention_days`), `peer_signatures` (`peer_id` or `hub`,
`public_key`, `signer_key`, `signature`, `signed_at`; rows for a
peer's old key stop matching after a rotation and go with the peer on
delete), `peer_routes` (`peer_id`, `prefix`, `advertised_at`,
`approved_at`, `approved_by`; foreign key on `peers` with cascade, so
the rows go with the peer). Endpoints, relay sessions and path state are ephemeral
and kept in memory in `control.EndpointTable`; a restart simply waits for
clients to re-report. Migrations are `NNNN_name.sql` files embedded and
applied in a transaction with the version recorded in `meta`.

Indexes: `peers(public_key)` unique, `peers(name)` unique,
`peers(owner_id)`, `enrollment_tokens(secret_hash)` unique,
`enrollment_tokens(expires_at)`, `audit_log(at)`.

## 7. Client state

| Path | Content | Mode |
|---|---|---|
| `/var/lib/thawr/client/node.key` | WireGuard private key | 0600 |
| `/var/lib/thawr/client/state.json` | server URL, TLS fingerprint, peer id, node secret, listen port, expected lock signer (`--lock-signer`), advertised routes and the selected exit node (spec 013) | 0600 |
| `/var/lib/thawr/client/netmap.json` | last netmap (public keys, addresses, endpoints) | 0600 |
| `/var/lib/thawr/client/pins.json` | accepted hub key, per-peer `(id, key)` by name, and the pinned lock record | 0600 |
| `/var/lib/thawr/client/lock.key` | Ed25519 lock private key; only on devices that ran `lock init` or `lock key`; removed by `down --forget` | 0600 |

macOS: `/Library/Application Support/Thawr/`. Windows: `%ProgramData%\Thawr\`.
The cached netmap lets the client restore WireGuard peers before the
server is reachable, so a mesh keeps working through a server outage as
long as endpoints have not changed.

## 8. External dependencies

| Module | Use | License |
|---|---|---|
| `golang.zx2c4.com/wireguard` (wireguard-go) | Userspace WireGuard, TUN | MIT |
| `golang.zx2c4.com/wireguard/wgctrl` | Configure kernel and userspace WireGuard | MIT |
| `golang.zx2c4.com/wireguard/windows` | Windows TUN (wintun) helpers | MIT; wintun.dll under its Prebuilt Binaries License |
| `modernc.org/sqlite` | SQLite, pure Go | BSD-3-Clause |
| `google.golang.org/grpc`, `google.golang.org/protobuf` | Control channel | Apache-2.0, BSD-3-Clause |
| `gopkg.in/yaml.v3` | Config and policy | MIT and Apache-2.0 |
| `golang.org/x/crypto` | argon2id password hashing | BSD-3-Clause |
| `golang.org/x/net`, `golang.org/x/sys` | DNS message codec (`dns/dnsmessage`), routing tables, syscalls, Windows service control manager (`windows/svc`) | BSD-3-Clause |
| `github.com/vishvananda/netlink` | Linux addresses and routes | Apache-2.0 |
| `github.com/google/nftables` | Linux receiver-side filter | Apache-2.0 |
| `tailscale.com/net/stun` (copied into `internal/stun` with license header) | STUN client and server codec | BSD-3-Clause |
| `github.com/skip2/go-qrcode` | QR export | MIT |
| `github.com/spf13/cobra` | CLI subcommands | Apache-2.0 |
| `golang.org/x/term` | Password prompt without echo | BSD-3-Clause |
| `github.com/bufbuild/buf` (build time only, via `go run`) | Protobuf compilation in `make proto` | Apache-2.0 |
| `github.com/santhosh-tekuri/jsonschema/v6` (tests only; pulls `github.com/dlclark/regexp2`) | Validates `client status --json` against `docs/status.schema.json` | Apache-2.0 (regexp2: MIT) |
| `github.com/makiuchi-d/gozxing` (tests only; pulls `golang.org/x/xerrors`) | Decodes the mobile QR back to the config in `TestQRRoundTrip` | Apache-2.0 (xerrors: BSD-3-Clause) |

All pure Go. The binary builds with `CGO_ENABLED=0` on Linux, macOS, and
Windows with Go 1.26 or newer (the minimum required by the gRPC and
`golang.org/x` releases in use).

## 9. Non-goals restated

No own cryptography, no Layer 2, no hosted control plane, no native
mobile apps in v1, no routers or exit-node use outside Linux in this
release (spec 013), no IPv6 overlay (spec 015; schema reserves
`ipv6`).
