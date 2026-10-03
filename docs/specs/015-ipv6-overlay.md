# Spec 015 — IPv6 overlay

Sprint 7. Depends on: 001 (bootstrap), 003 (netmap sync), 006 (policy,
filter), 008 (mobile QR), 010 (names), 013 (exit nodes). Packages:
`internal/config` (`overlay.ipv6`), `internal/store` (migration 0007,
`ipv6` and `ipv6_capable`), `internal/control` (address derivation,
netmap, policy compiler), `internal/api` (proto fields, REST, mobile
config), `internal/server` (prefix persistence, hub addresses, hub
filter, forwarding), `internal/wg` (addresses, routes, nftables and
userspace filters, forwarding and NAT66 per platform),
`internal/client` (capability flag, state, config, status),
`internal/dns` (AAAA, `ip6.arpa`), `cmd/thawr`, `web/`.

## Goal

Every peer has an IPv6 address next to its IPv4 one, and everything
that knows addresses knows both: WireGuard, the operating system's
addresses and routes, the packet filters, names, the phone QR, status,
the admin views and exit nodes. Applications that prefer IPv6, or
speak only IPv6, work inside the network, and a device whose internet
leaves through an exit node no longer leaks its native IPv6 around it.

The IPv6 addresses come from a unique local prefix (ULA, RFC 4193)
that the server picks once and keeps. They are reachable only inside
the tunnel, like the IPv4 overlay; nothing is announced to the
internet.

## User story

As the owner I upgrade the server and then my devices. The server
picks `fd3a:9c1e:44b0:0::/64` on its first start and keeps it. My
laptop, `100.64.0.7`, now also has `fd3a:9c1e:44b0::6440:7`;
`ping6 nas.thawr` works, `ssh nas.thawr` uses IPv6 when the client
prefers it, and `client status` shows both addresses. A phone I add
afterwards gets both addresses in its QR. With `client exit-node nas`
my IPv6 traffic to the internet leaves through the NAS as well. A
device I have not upgraded yet keeps working on IPv4.

## Addresses

- **Prefix.** `overlay.ipv6` in the config, a `/64` inside `fd00::/8`.
  Empty (the default) means: the server generates one on first start
  (`fd` + 40 random bits from `crypto/rand` + subnet `0`, RFC 4193)
  and stores it in the database (meta `overlay_ipv6`), so backups and
  restores keep it. A configured prefix is stored the same way. A
  start whose configured prefix differs from the stored one is refused
  ("overlay.ipv6 changed from X to Y; every peer's IPv6 address would
  change"); to change it the operator deletes the meta row on purpose
  (documented, out of the normal path).
- **Derivation.** A peer's IPv6 address is the prefix with the peer's
  IPv4 address in its last 32 bits: `100.64.0.7` →
  `<prefix>::6440:7`. The hub (`100.64.0.1`) is `<prefix>::6440:1`.
  There is no second allocator; IPv4 and IPv6 always come in pairs,
  and a peer's IPv6 address never changes while its IPv4 one does not.
- **Store.** Migration 0007 adds a unique index on `peers.ipv6` (the
  column has existed since 0001) and `peers.ipv6_capable` (default 0).
  At start the server fills `ipv6` for every peer that has none.
- `overlay.cidr` stays IPv4; nothing about the IPv4 overlay changes.

## Compatibility: the capability flag

A client from before this spec rejects IPv6 routes and would break on
an IPv6 entry in its netmap. Every client from this release on sends
`ipv6: true` in `EnrollRequest` and `SyncRequest`; the server stores it
per peer (`ipv6_capable`) and:

- sends a peer its own IPv6 address, the IPv6 prefix and IPv6 filter
  rules only when that peer is capable;
- lists another peer's IPv6 address and `/128` AllowedIPs to a capable
  peer only when the other peer is capable too (an address no device
  has configured would only blackhole traffic);
- sends an incapable peer exactly the netmap it gets today.

Phones added from this release on are capable (their QR carries both
addresses); phones added earlier keep their IPv4-only config until
re-added. The hub is always capable.

## Behaviour

### Server

- Gives the hub interface both addresses (`100.64.0.1/10`,
  `<prefix>::6440:1/64`) and every capable peer a `/128` next to its
  `/32` in the hub's AllowedIPs.
- Enables IPv6 forwarding for the hub (Linux:
  `net.ipv6.conf.all.forwarding`; macOS: `net.inet6.ip6.forwarding`).
  Linux stops accepting router advertisements on interfaces with
  `accept_ra=1` once forwarding is on, which would take a VPS's own
  IPv6 default route away; those interfaces are moved to `accept_ra=2`
  first, and both settings are restored when the server stops.
- The hub filter (phones) gets the IPv6 rules described below.
- Policy: `FilterFor` and `ForwardFor` emit, for each source, a rule
  per address the source has. `internet` stands for `0.0.0.0/0` and
  `::/0`. A CIDR selector may be an IPv6 prefix or address and matches
  peers' IPv6 addresses. Advertised subnet routes stay IPv4 (out of
  scope).
- Exit nodes: an approved exit node that is capable carries `::/0` as
  well; a capable client using it gets `::/0` in that peer's
  AllowedIPs. An exit node that is not capable carries IPv4 only.
- The mobile config carries `Address = <v4>/32, <v6>/128` and
  `AllowedIPs = <overlay.cidr>, <prefix>/64`; `DNS` stays the hub's
  IPv4 address.

### Client

- Sends `ipv6: true`, stores `ipv6` and `overlay_ipv6` in
  `state.json` (filled from the netmap for devices enrolled earlier),
  configures both addresses on its interface and the `/128`s in
  WireGuard.
- Exit node: routes `::/0` through the exit node when the netmap
  carries it, with Linux policy routing for both families.
- Status: `self.ipv6` and `peers[].ipv6` in `client status --json`
  (optional fields in `docs/status.schema.json`), both addresses on the
  self line and an `IPV6` column in the table.

### Data plane (`internal/wg`)

- **Addresses and routes.** Linux: netlink with both families, IPv6
  addresses without duplicate-address detection (`IFA_F_NODAD`).
  macOS: `ifconfig inet6 … prefixlen N alias`, `route -inet6`.
  Windows: `netsh interface ipv6`. Routes accept IPv6 prefixes; the
  exit route is the pair `0.0.0.0/0`, `::/0`.
- **Filter.** nftables and the userspace filter match IPv6 like IPv4:
  source, destination, protocol and port, a second set of visible
  addresses. ICMPv6 echo request (128) is governed by the same rule as
  ICMP echo; Packet Too Big, Destination Unreachable, Time Exceeded
  and Parameter Problem (types 2, 1, 3, 4) and neighbour discovery
  (133–137) are always accepted, since path MTU discovery breaks
  without them. The userspace filter walks hop-by-hop, routing,
  destination-options and fragment headers to find the transport
  header.
- **Router.** An exit node masquerades `<prefix>/64` like the IPv4
  overlay (NAT66 in the same `inet thawr` table) and enables IPv6
  forwarding with the same `accept_ra` care as the server.

### Names

- `<name>.thawr` answers AAAA with the peer's IPv6 address (capable
  peers), A as before; `hub.thawr` answers both.
- Reverse lookups under `ip6.arpa` for the ULA prefix answer the name.
- The resolvers keep listening on IPv4 only and answer both record
  types there; the registrars keep pointing the system at that address,
  so no resolver needs an IPv6 listener.

## Acceptance criteria

1. A fresh server generates a ULA `/64`, prints it at start, and keeps
   it across restarts and a backup restore; a changed `overlay.ipv6`
   refuses to start.
2. After an upgrade every existing peer has an IPv6 address derived
   from its IPv4 address; `admin peer list` shows both.
3. Two upgraded Linux clients ping each other's IPv6 address and
   `<name>.thawr` over IPv6; a policy that denies a port denies it on
   IPv6 too.
4. A client from before 015 enrolled against the upgraded server keeps
   syncing and reaching peers over IPv4; its netmap is unchanged.
5. A phone added after the upgrade reaches peers over IPv6 through the
   hub; its QR carries both addresses.
6. With an upgraded exit node, `curl -6 https://ifconfig.co` on a
   client using it shows the exit node's public IPv6 address.
7. `dig AAAA <name>.thawr` and `dig -x <ipv6>` answer on every client
   and through the hub.

## Test cases

- `internal/control`: `TestIPv6For` (table); netmap for capable and
  incapable targets, the incapable one equal to the pre-015 netmap;
  exit node `::/0` only between capable peers.
- `internal/control/policy`: dual rules per source, `internet` both
  families, IPv6 CIDR selector.
- `internal/server`: prefix generate/keep/mismatch; backfill at start;
  hub AllowedIPs.
- `internal/store`: migration 0007, `BackfillIPv6`, unique `ipv6`.
- `internal/api`: mobile config with both families; REST `ipv6`.
- `internal/wg`: route and address command builders per platform;
  nftables IPv6 rules; userspace filter IPv6 and ICMPv6 table,
  extension headers; `accept_ra` handling against a fake `/proc`.
- `internal/client`: config with both families, exit `::/0`, status.
- `internal/dns`: AAAA, `ip6.arpa` PTR.
- `tests/` (netns): `ping -6` between clients and through the hub,
  AAAA, IPv6 filter drop, IPv6 egress through an exit node, an old
  client without the flag.

## Out of scope

- IPv6 subnet routes (`--advertise-routes` with IPv6 prefixes).
- IPv6 underlay changes (endpoints, STUN, relay); this spec is about
  addresses inside the tunnel.
- A globally routed overlay prefix; the overlay stays ULA.
- An IPv6-only overlay (IPv4 stays mandatory).
- IPv6 through an exit node that is not upgraded; such an exit node
  carries IPv4 only, and native IPv6 on the client bypasses it as
  before.
