# Spec 016 — Separate relay nodes

Sprint 8. Depends on: 002 (enrollment tokens, TLS pinning), 003 (netmap
sync), 004 (paths, reach requests), 005 (relay protocol), 009 (service
install), 014 (metrics). Packages: `internal/relay` (ticket auth and
remote visibility on the server side, several connections on the client
side), `internal/store` (migration 0008, `relays`, `relay_tokens`,
`relay_tickets`), `internal/control` (relay registry, tickets, netmap),
`internal/api` (proto: `RelayControl` service, netmap fields; REST),
`internal/relaynode` (new: composes the standalone relay, as
`internal/server` composes the server), `internal/client` (home relay,
relay choice per peer), `internal/svc`, `cmd/thawr`, `web/`.

## Goal

A relay can run on a host of its own, close to the devices that need
it, and take relayed traffic off the server. The relay inside the
server stays, needs no configuration and is what everything falls back
to, so a network with one host works exactly as before.

## User story

As an admin whose server sits in Frankfurt while half the team is in
Riyadh, I start `thawr relay` on a small host in Riyadh with a token
from the server. Devices near it use it when they cannot connect
directly; `thawr client status` names the relay a peer goes through. If
that host disappears, the same peers continue over the server's relay
within seconds and nobody has to do anything.

## What a relay node is, and is not

A relay node is not a peer. It has no WireGuard key, no overlay
address, no name in the zone, no place in the policy file and no record
under the network lock (spec 012). It forwards the frames of spec 005,
unchanged, between devices that hold a ticket from the server, and it
learns from the server which pairs may talk. It never holds a node
secret, a session key or a policy file.

ADR 0005 already names `thawr relay` as the phase 2 form of a separate
relay in the same binary; this spec adds the subcommand and changes no
ADR.

## Enrolling a relay

```
thawr admin relay token [--name riyadh-1] [--ttl 1h]      # on the server
thawr relay up --server https://vpn.example.com --token <token> \
      --public-url https://relay-riyadh.example.com:443 [--listen :443] \
      [--state-dir /var/lib/thawr-relay]
thawr relay status [--json]
thawr relay install | uninstall | start | stop             # service, as for the client
thawr admin relay list | show <name> | delete <name>
```

- Relay tokens are their own kind, in their own table: one-time,
  hashed, expiring (default 1 h), created only by an admin. An
  enrollment token for a peer is refused by `RelayControl.Register` and
  a relay token is refused by `Enroll`; both with `PermissionDenied`
  and the same message, so a token's kind is not disclosed.
- On first `relay up` the node pins the server's TLS fingerprint the way
  a client does (spec 002: shown once, `--fingerprint` to pre-pin),
  generates a self-signed TLS key and certificate for its own listener
  (`crypto/ecdsa` P-256, as the server does in spec 001), and calls
  `Register(token, name, public_url, tls_fingerprint)`. The server
  answers with a relay id and a relay secret (32 random bytes). The
  state directory holds `relay.json`, `relay.secret`, `tls.key` (0600)
  and `tls.crt`; later starts need no token.
- `--public-url` is what devices dial. It must be `https`, with a host
  and a port; the server stores it as given and does not resolve it.
  `--listen` is the local bind address (default `:443`).
- A relay's name follows the rules of a peer name (spec 010) and is
  unique among relays; it is not a DNS name in the zone.
- `admin relay delete` removes the relay, its secret and its tickets;
  the next netmap no longer lists it and its control stream is closed.
- Audit actions (spec 011): `relay.token`, `relay.register`,
  `relay.delete`. Going online or offline is logged, not audited.

## Relay to server: `RelayControl`

A new gRPC service on the server's existing listener, authenticated
with the relay secret as a bearer credential over the pinned TLS
connection (as clients do with the node secret, decision D7).

| RPC | Purpose |
|---|---|
| `Register(RegisterRelayRequest) RegisterRelayResponse` | One-time token to relay id and secret |
| `Attach(stream RelayEvent) stream RelayDirective` | The relay's one long-lived stream: heartbeat, admission, visibility, absences, counters |

On `Attach` the relay sends, as `RelayEvent`:

- `hello` (version, public_url, tls_fingerprint) first; a fingerprint
  or URL that differs from the registered one replaces it and bumps the
  netmap generation, so a relay whose certificate was regenerated is
  usable again without re-enrolling.
- `heartbeat` every 10 s with sessions, frames, bytes and drops.
- `admit(request_id, ticket)` when a device presents a ticket.
- `closed(peer_key)` when a session ends.
- `absent(src, dst)` when a device sends to a visible peer that has no
  session here (rate limited as in spec 005).

The server sends, as `RelayDirective`:

- `admitted(request_id, peer_key, visible_keys, generation)` or
  `refused(request_id)`.
- `visibility(peer_key, visible_keys, generation)` for every admitted
  session whose visible set changed with a netmap generation.
- `revoke(peer_key)` when a peer is deleted, its key rotated or its
  ticket withdrawn; the relay closes that session within 5 s.

The relay answers the visibility check of spec 005 from the sets it was
sent, never by asking per frame. An `absent` event feeds the server's
existing reach request (spec 004), so the destination joins that relay
the same way it joins the server's relay today.

A relay is **online** while its stream is attached and a heartbeat
arrived within 30 s. Only online relays are listed in netmaps; going
online or offline bumps the generation.

When the relay loses the server: it keeps the sessions it has, with the
visibility it last received, for `--server-grace` (default 5 min,
0 closes them at once) and admits nobody new, since it cannot check a
ticket. After the grace period it closes every session. It reconnects
with the backoff of spec 005.

## Device to relay: tickets, never the node secret

A device must not present its node secret to a relay: a relay host is
easier to take over than the server, and a node secret is a device's
whole control-plane identity.

- For each device that said it supports relay nodes, and each online
  relay, the server issues a **ticket**: 32 bytes from `crypto/rand`,
  bound to that device and that relay, valid for `relay.ticket_ttl`
  (default 1 h). The server stores the SHA-256 of the ticket, the peer
  id, the relay id and the expiry (`relay_tickets`), and puts the
  ticket itself in that device's netmap only. A ticket past half its
  lifetime is replaced in the next netmap (the keepalive resend is
  enough); the old one stays valid until it expires.
- The device opens `GET /relay` on the relay's `public_url` with
  `Upgrade: thawr-relay/1` and `Authorization: Bearer <ticket>`,
  verifying the relay's certificate against the fingerprint from the
  netmap and nothing else (no CA, no hostname check).
- The relay passes the ticket to the server in `admit`. The server
  looks up its hash, checks relay, expiry and that the peer still
  exists, and answers with the peer's public key and visible set. The
  relay then responds `101`; anything else is `401` before a frame is
  read. A relay that does not get an answer within 5 s answers `503`.
- A ticket is not consumed by use (a device reconnects with it) and is
  useless at any other relay and at the server. Deleting a peer,
  rotating its key or deleting the relay deletes its tickets.

Frames, limits, keepalive, queueing and the WireGuard message-type
filter are those of spec 005 on both ends; `relay.max_bytes_per_second`
is sent to the relay in `admitted` and applies there too.

## Netmap

```
message NetMap  { ... repeated RelayNode relays = 10; }
message RelayNode {
  string id = 1; string name = 2;
  string url = 3;              // the relay's public_url
  string tls_fingerprint = 4;  // SHA-256 of its certificate, hex
  bytes  ticket = 5;           // this device's ticket for this relay
  int64  ticket_expires = 6;   // unix seconds
}
message NetPeer { ... string home_relay = 18; }  // relay id; empty = the server
```

- A device says it supports relay nodes with `relay_nodes = true` in
  `Enroll` and `Sync`, as it does for IPv6 (spec 015). Devices that do
  not get no `relays` and no tickets, their `home_relay` is always
  empty, and they keep using the server's relay as before.
- The server's own relay is never listed. It is the relay with the
  empty id, always available, reached with the node secret as in
  spec 005.
- The list is sorted by name. The order carries no preference: the
  server cannot know which relay is near a device, the device measures.
- Field numbers are fixed here; `make proto` regenerates the code.

## Choosing a relay

Relays do not talk to each other. Two devices meet on one relay, and
which one is decided per destination, as in DERP:

- **Home relay.** A device with relayed peers, or asked to join by a
  reach request, picks one home relay: the online relay with the lowest
  measured latency, or the server when no relay node answers. It keeps
  a session there and reports the choice in `ReportEndpoints`
  (`home_relay`); the server puts it in every netmap that lists the
  device and bumps the generation when it changes.
- **Sending.** To reach a relayed peer a device sends through *that
  peer's* home relay. It therefore holds at most one connection per
  distinct home relay among its relayed peers, each opened on first use
  and closed after 5 min without a proxy on it, exactly as the single
  connection of spec 005. A peer's proxy address on the loopback does
  not change when its home relay does.
- **Measuring.** Latency is the round trip of one `PING` frame on a
  fresh authenticated connection, taken for every listed relay and for
  the server when the first peer needs a relay and every 10 min while
  any peer is relayed. A device changes its home only for a relay that
  is at least 20 % and 10 ms faster, so two close relays do not trade
  places.
- **Falling back.** If a device cannot connect to a peer's home relay
  within 5 s, or is refused, it sends through the server's relay
  instead and reports the path as `relay`; the server's reach request
  brings the peer onto the server's relay, as today. If a device loses
  its own home relay it picks the next best, the server last, and
  reports it. A device always accepts frames on every relay it has a
  session on, so both directions keep working while homes change.
- A pair where either side lacks `relay_nodes` uses the server's relay
  in both directions.

The path state machine of spec 004 is unchanged: `relay` is still one
state. Which relay carries it is an attribute of the path.

## Status, admin, metrics

- `client status`: a relayed peer's path reads `relay (riyadh-1)`, or
  `relay` for the server's. `--json` adds `relay` (the name, empty for
  the server) per peer and `home_relay` at the top level;
  `docs/status.schema.json` gains both.
- `admin relay list`: name, URL, online or offline since, sessions,
  version. `admin relay show <name>`: the same plus fingerprint,
  registered at, bytes and drops. REST: `GET /api/v1/relays`,
  `POST /api/v1/relays/tokens`, `DELETE /api/v1/relays/{id}` (admin
  role). The admin UI gets a "Relays" table under the peers table.
- `relay status`: server reachable or not, sessions, frames, bytes,
  drops, grace period remaining when the server is away. Exit codes as
  for `client status`.
- Metrics (spec 014): `thawr_relay_nodes{state="online|offline"}` and
  the existing relay counters with a `relay` label holding the relay
  id or `server`; never a peer key or a name.

## Configuration

Server, new keys with defaults (a config without them is unchanged):

```yaml
relay:
  max_bytes_per_second: 0   # existing; now also sent to relay nodes
  ticket_ttl: 1h            # 5m to 24h
```

The relay node has flags and a state directory, no config file. It
opens one TCP port and nothing else: no STUN, no UDP, no WireGuard
interface, no database.

## Threat model

Rows to add to `docs/THREAT_MODEL.md` when the implementation lands; no
existing row gets weaker.

| Threat | Answer |
|---|---|
| A relay host is taken over | It sees which keys exchange packets through it, how much, and from which addresses, as the server's relay does. It holds ciphertext, tickets valid only at itself and its own relay secret: no node secret, no peer key, no policy. It can drop or delay. It can forward a frame between two sessions that are not visible to each other, which the receiver's WireGuard device discards because it has no such peer. `admin relay delete` removes it from every netmap within one generation |
| A relay secret is stolen | The thief can attach as that relay and see what it would see. The admin deletes the relay and enrols it again |
| A ticket is read off a device | It admits its holder at one relay as that device until it expires (1 h) or the peer is deleted or rotated, and reaches only what that device may reach. It is no credential for the control plane |
| A device is pointed at a false relay | The relay list and fingerprints come from the server over the pinned connection; a server that lies about them could already withhold or invent peers (existing row on a malicious server). The lock is unaffected: a relay never sees plaintext and vouches for nothing |
| The server is unreachable for the relay | No new admissions; existing sessions end after the grace period. Fails closed |

## Acceptance criteria

- [ ] `thawr relay up` with a relay token registers, appears in
      `admin relay list` as online within 10 s, and is listed in the
      netmap of every device that sent `relay_nodes`.
- [ ] A peer enrollment token cannot register a relay and a relay token
      cannot enrol a peer.
- [ ] Two devices behind symmetric NATs (netns), with the server's
      `/relay` route blocked for both, exchange `ping` through a
      standalone relay within 10 s; `client status` names it.
- [ ] A device presenting its node secret, an expired ticket, a ticket
      of another relay or no credential gets `401` from a relay node
      before any frame is read. No test fixture or log line contains a
      ticket.
- [ ] A frame to a peer that is not visible is not forwarded by a relay
      node and yields `PEER_GONE`; after a policy reload that removes a
      grant, forwarding between that pair stops within 5 s.
- [ ] Deleting a peer closes its session on every relay node within 5 s.
- [ ] Stopping the relay node: relayed pairs continue over the server's
      relay within 15 s without a restart of either client.
- [ ] Stopping the server: sessions on the relay node keep forwarding
      for the grace period, a new device is refused, and after the
      grace period every session is closed.
- [ ] A device from before this spec (no `relay_nodes`) and a new one
      still reach each other through the server's relay.
- [ ] With two relay nodes, a device's home is the one with the lower
      measured latency and does not change while the difference stays
      under the threshold (injected clock and latencies).
- [ ] The relay node's state directory is created 0700 and the files
      holding secrets 0600, restricted through `internal/fsperm` on
      Windows, as for the client.

## Test cases

- `internal/store`: `TestRelayTokensOneTime`, `TestRelayTicketsExpire`
  (injected clock), `TestDeletePeerDeletesTickets`,
  `TestMigration0008`.
- `internal/control`: `TestRelayRegister`, `TestRelayTokenKindsDoNotMix`,
  `TestRelayOnlineOffline` (injected clock), `TestTicketIssueAndRenew`,
  `TestNetmapRelaysOnlyForCapableClients`, `TestHomeRelayInNetmap`.
- `internal/api`: `TestRelayControlAuth`, `TestAttachAdmitRefuse`,
  `TestAttachVisibilityOnGeneration`, `TestAttachRevokeOnDelete`,
  `TestRESTRelays` (roles).
- `internal/relay`: `TestTicketAuth` (401 cases), `TestRemoteVisibility`,
  `TestServerGrace` (injected clock), `TestClientPerHomeConnections`,
  `TestClientFallsBackToServer`, `TestHomeChoiceHysteresis`.
- `internal/client`: `TestStatusNamesRelay`, golden files for
  `status --json`.
- Integration (netns): `TestStandaloneRelaySymmetricNATs`,
  `TestStandaloneRelayFailover`, `TestStandaloneRelayServerDown`.

## Delivery

One story each, in this order (sprint 8 of `docs/roadmap/sprints.md`):

1. S8-2 — store, registry, tokens, tickets, `RelayControl`, netmap
   fields, `admin relay`, REST, audit, metrics. Nothing uses a relay
   node yet.
2. S8-3 — `thawr relay`: `internal/relaynode`, ticket admission and
   remote visibility in `internal/relay`, `relay install`, the netns
   test with one relay.
3. S8-4 — client: capability flag, home relay, a connection per home,
   measuring, falling back, status; the failover tests.

## Out of scope

- Relays forwarding to each other; a pair always meets on one relay.
- A relay chosen by an admin per peer, per group or per region, and
  latency reported to the server for display.
- A browser-trusted certificate (ACME) for a relay node: devices pin
  the fingerprint from the netmap.
- STUN on a relay node. Endpoint discovery stays with the server.
- Phones and other static peers: they use the hub (spec 008).
- Bandwidth accounting or quotas per user.
