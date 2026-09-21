# Spec 013 — Exit nodes and subnet routers

Sprint 5. Depends on: 003 (netmap sync), 006 (policy, filter), 007
(status document), 011 (audit log). Packages: `internal/store`
(`peer_routes`), `internal/control` (routes service, policy compiler,
netmap), `internal/api` (`AdvertiseRoutes` RPC, REST routes view),
`internal/client` (route installation, exit-node selection, router
forwarding), `internal/wg` (routes and fwmark per platform, forward
and nat rules), `cmd/thawr` (`client up` flags, `client exit-node`,
`admin peer routes`, status), `web/`.

## Goal

Until now a peer is reachable only at its own overlay address. Two
things people run a private network for need more: a machine on a LAN
that has no client of its own (a printer, a NAS behind a router, a
whole office subnet), and a laptop on hostile Wi-Fi that wants all of
its internet traffic to leave through a machine at home. Both are the
same mechanism: one peer carries traffic for addresses that are not
its own. A **subnet router** advertises the prefixes behind it; an
**exit node** advertises `0.0.0.0/0`. Nothing is carried until an
admin has approved the advertisement and the policy says who may use
it; the client then installs the route and the router forwards.

Default deny stays: an approved route reaches only the peers a policy
rule grants it to, ports included, and the router enforces that on its
forwarding path with the same filter it already runs for its own
ports. A phone stays out of this spec (its tunnel ends at the hub).

## User story

As the owner I run `thawr client up --advertise-routes 10.1.0.0/24` on
the office gateway and `thawr admin peer routes approve office-gw
10.1.0.0/24` on the server. I add `dst: ["10.1.0.0/24:*"]` for
`group:devs` to the policy. Every dev laptop now reaches the printer
at `10.1.0.20` through the gateway, and `client status` shows the
route and the peer it goes through. At home I run `thawr client up
--advertise-exit-node` on the NAS, approve it, and allow `internet:*`
for myself. On the train, `thawr client exit-node nas` sends my whole
internet through the NAS; `thawr client exit-node off` stops that.

## Commands

```
thawr client up --advertise-routes 10.1.0.0/24,10.2.0.0/16   # this device carries these prefixes (Linux)
thawr client up --advertise-exit-node                        # this device carries 0.0.0.0/0 (Linux)
thawr client exit-node <name> | off | status                 # route this device's internet through <name> (Linux)
thawr client status                                           # ROUTES line, advertised prefixes and their approval

thawr admin peer routes list <name>                           # advertised prefixes of a peer with approval state
thawr admin peer routes approve <name> <prefix>|--all         # audit route.approve
thawr admin peer routes revoke <name> <prefix>|--all          # audit route.revoke
thawr admin peer show <name>                                  # gains the routes
```

Policy file:

```yaml
acls:
  - action: accept
    src: [group:devs]
    dst: ["10.1.0.0/24:*", "10.2.0.0/16:22"]   # a CIDR outside the overlay is a subnet route
  - action: accept
    src: [markus]
    dst: ["internet:*"]                          # may use an approved exit node
```

`client status` with a route and an exit node:

```
thawr 0.2.0 · alice-laptop 100.64.0.7 · server vpn.example.com:8443 connected (netmap #42, 3s ago)
WireGuard: kernel · thawr0 · listen 41820 · NAT: cone (reflexive 203.0.113.9:41820) · DNS: .thawr via resolved · lock: off
Routes: 10.1.0.0/24 via office-gw · exit node: nas

PEER          IP            KIND     OWNER   PATH                           HANDSHAKE   RX / TX
office-gw     100.64.0.3    server   -       direct 198.51.100.4:51820      12s         1.2 MB / 340 kB
nas           100.64.0.9    server   -       direct 203.0.113.7:51820       3s          80 MB / 6 MB
```

On the router:

```
Routes: advertising 10.1.0.0/24 (approved), 0.0.0.0/0 (pending approval: thawr admin peer routes approve office-gw 0.0.0.0/0)
```

## Behaviour

### Server

- Migration `0005_routes.sql`: `peer_routes(peer_id, prefix, advertised_at,
  approved_at NULL, approved_by NULL)` with the primary key `(peer_id,
  prefix)` and a foreign key on `peers` with cascade delete. `prefix`
  is the canonical CIDR text (network address, IPv4 only in this spec;
  `0.0.0.0/0` is the exit node).
- `AdvertiseRoutes(prefixes[])`, node-authenticated: the daemon sends
  its full advertised set at every stream start and whenever the
  flags change. Prefixes must be valid IPv4 CIDRs, canonical, not
  inside the overlay range, at most 64, no duplicates; the whole
  request is rejected otherwise. Prefixes not stored are inserted
  unapproved (audit `route.advertise`, actor `peer:<name>`, details
  prefix); stored prefixes missing from the request are deleted
  (audit `route.withdraw`), approval included, so a router that stops
  advertising and starts again is approved again by a person. The
  reply lists every stored prefix with its approval, which the client
  shows. Static peers cannot advertise (no daemon).
- `admin peer routes approve|revoke` over the admin socket and REST
  (`PUT /api/v1/peers/{name}/routes/{prefix}` with `{approved: bool}`,
  `GET /api/v1/peers/{name}/routes`), admin role only, audit
  `route.approve` and `route.revoke` with actor, target peer and the
  prefix. Approving a prefix nobody advertises is an error. Revoking
  keeps the row unapproved so the router's status says so.
- **Policy.** `dst` accepts, next to the existing selectors, an IPv4
  CIDR outside the overlay (a subnet route) and the word `internet`
  (any approved exit node). Ports apply to the destination inside the
  subnet. Validation rejects a CIDR that overlaps the overlay or that
  is not canonical. `Compile` receives the approved routes and yields,
  per source peer `C` and router `R`, the **forward rules** `{prefix,
  proto, lo, hi}` for each approved prefix of `R` that a rule's `dst`
  CIDR lies inside (the rule's CIDR, not the advertised one, is what
  the forward rule carries, so `10.1.0.0/24:22` through a router that
  advertises `10.0.0.0/8` forwards only that /24) and, for `internet`,
  `{0.0.0.0/0, proto, ports}` through each approved exit node.
  `Visible(C, R)` becomes true when `C` has a forward rule through
  `R` (a client needs the router's key), and only then; nothing else
  about `Allowed(C, R)` changes, so a route grants no port on the
  router itself. `FilterFor(R)` gains the forward rules with `C`'s
  overlay address as source; the netmap carries them in a separate
  `forward` list so the client can install them in the forward chain.
- **Netmap.** The prefixes the receiver may reach through a peer ride
  in that peer's `allowed_ips` next to its /32: the rule CIDRs from
  its forward rules through `R`, deduplicated, each assigned to
  exactly one router when several advertise it (lowest peer id wins,
  so WireGuard's one-peer-per-prefix rule holds); the client derives
  the OS routes from every `allowed_ips` entry that is not a peer's
  own /32. `NetPeer.exit_node` is true when the receiver may use that
  peer as an exit node; `0.0.0.0/0` is **not** in `allowed_ips`
  because using an exit node is the receiver's choice. `SelfInfo.
  advertised[] {prefix, approved}` tells a router what the server
  knows about it. The hub is never a router in this spec.

### Client

- `--advertise-routes` and `--advertise-exit-node` are persisted in
  `state.json`; a later `client up` without the flags keeps the stored
  set, one with the flags replaces it (an empty list withdraws), and
  advertising is the device's own statement, so no exit 2 for a
  change, unlike `--lock-signer`. The daemon calls
  `AdvertiseRoutes` after enrolment and at every stream start. Both
  flags require Linux with nftables: the router role needs `ip_forward`
  and a nat table, and the receiver-side filter (spec 006) is what
  enforces the forward rules; on macOS and Windows the flags exit 2
  with "subnet routers need Linux in this release".
- **Router.** With prefixes advertised the daemon sets
  `net.ipv4.ip_forward=1` (recorded so `client down` restores the
  previous value only when it changed it) and extends the `inet thawr`
  table: chain `forward` (hook forward, policy drop) with `ct state
  established,related accept`, one `iifname thawr0 ip saddr <C> ip
  daddr <prefix> <proto> dport <ports> accept` per forward rule from
  the netmap, and `oifname thawr0 ct state established,related
  accept`; chain `postrouting` (type nat) with `oifname != thawr0 ip
  saddr <overlay> ip daddr <advertised prefix> masquerade` per
  advertised prefix (`0.0.0.0/0` masquerades everything leaving the
  tunnel). The router forwards only prefixes **it** advertised, taken
  from its own state, never from the netmap, so a server that
  invents a route on a peer sends traffic into a drop rule, not into
  the LAN. With `wireguard-go` on Linux the same nftables rules apply
  (the TUN is a kernel interface and forwarding is the kernel's); the
  userspace filter passes packets whose destination is not the
  device's own address on to the kernel where the forward chain
  decides. Rules are replaced atomically on every netmap, as today.
- **Routes.** For every `NetPeer.routes` prefix the client adds the
  prefix to that peer's `AllowedIPs` and installs a route through
  `thawr0` (`ip route replace <prefix> dev thawr0` on Linux, `route -n
  add -net <prefix> -interface utunN` on macOS, `netsh interface ipv4
  add route <prefix> interface=<idx>` on Windows), removes routes that
  left the netmap, and removes them all on `client down`. A held peer
  (`key_changed`, `unsigned`) contributes no routes, as it contributes
  nothing else. A prefix that would shadow the server's public address
  or the overlay is refused with a logged warning. Routes appear in
  status: `routes[] {prefix, via}`.
- **Exit node.** `thawr client exit-node <name>` (local API `POST
  /exit-node/{name}`, `off`, `GET /exit-node`) selects a peer whose
  `exit_node` flag is set; the selection is persisted in `state.json`
  and survives restarts. With a selection the client adds `0.0.0.0/0`
  to that peer's `AllowedIPs` and, on Linux, routes with a fwmark so
  the tunnel's own packets never enter the tunnel: `fwmark` on the
  WireGuard device (kernel: `wgctrl`; `wireguard-go`: `SO_MARK` on
  the bind), `ip rule add not fwmark <mark> lookup <table>`, `ip rule
  add lookup main suppress_prefixlength 0`, `ip route add default dev
  thawr0 table <table>`; mark and table are the fixed number
  `0x7a77`. macOS and Windows refuse the selection in this release:
  without a fwmark the tunnel's own packets would enter the tunnel, and
  the alternative (half routes plus host routes to the endpoint and the
  server, refreshed on every path change) is left for a later spec. When the selected peer is
  held, offline for longer than the handshake timeout, or loses the
  flag in a netmap, the default route is removed and status says
  `exit node: nas (unavailable)`; traffic then leaves the normal way,
  which the status makes visible rather than silently failing closed
  (a kill switch is out of scope). DNS is untouched: names outside
  `.thawr` still use the host's resolvers, which the status line notes
  with `dns: local`.
- **Status.** `routes[] {prefix, via}`, `exit_node {name, state:
  active|unavailable|off}`, `advertised[] {prefix, approved}`; the
  `Routes:` line as above, omitted when nothing applies. `admin peer
  show` prints `advertised` with approval and `serves` (the peers that
  currently hold a route through it, from the compiled policy).

## Acceptance criteria

1. Router `R` advertises `10.1.0.0/24`; before approval no netmap
   carries it and `R`'s status says `pending approval`. After `admin
   peer routes approve` and a policy rule `dst: ["10.1.0.0/24:*"]` for
   `C`, `C`'s netmap lists the route on `R`, `C`'s status shows
   `10.1.0.0/24 via R`, and `ping 10.1.0.20` from `C` reaches a host
   behind `R` (netns). A peer without the rule has no route and no
   key for `R` (unless another rule makes them visible).
2. Ports: with `dst: ["10.1.0.0/24:22"]`, TCP 22 to the LAN host
   connects and TCP 80 times out; the counters in `R`'s status show the
   drop. `established,related` lets the reply through.
3. Revoking the approval, withdrawing the advertisement (`client up`
   without the flag) or removing the rule takes the route out of `C`
   within one netmap; the route is gone from `C`'s routing table.
4. Two routers advertise the same prefix: `C` routes through one of
   them, deterministically, and WireGuard has the prefix on one peer
   only.
5. Linux: `client exit-node nas` on `C` after `internet:*` is allowed:
   `C`'s traffic to an address outside the overlay leaves `nas`
   masqueraded; the control connection and the WireGuard endpoint keep
   working (fwmark); `exit-node off` restores the previous routing;
   `client down` leaves no rule, route or mark behind. Selecting a peer
   without the flag exits 2.
6. The server invents a route on `R` that `R` never advertised: `C`
   installs it (the netmap said so) and packets reach `R`'s forward
   chain, which drops them; nothing enters `R`'s LAN.
7. `AdvertiseRoutes` rejects an overlay prefix, a non-canonical one,
   and more than 64; every approve, revoke, advertise and withdraw is
   in `admin audit`.

## Test cases

- `internal/store`: routes put/list/approve/delete with cascade on
  peer delete.
- `internal/control`: `TestAdvertiseRoutesReplacesSet` (insert,
  withdraw, approval reset, audit rows), `TestApproveRequiresAdvertised`,
  `TestCompileForwardRules` (rule CIDR inside the advertised prefix,
  ports, `internet`, visibility only through the route),
  `TestNetMapRoutesOnePeerPerPrefix`, `TestNetMapExitNodeFlag`.
- `internal/config` / policy: `TestPolicyRouteSelectors` (CIDR
  outside the overlay, overlap with the overlay rejected,
  `internet`).
- `internal/api`: `TestAdvertiseRoutesRPC` (validation, reply),
  `TestRoutesEndpoint` (approve, revoke, list, admin only).
- `internal/wg`: `TestForwardRuleset` (golden nftables text with
  forward and nat chains), `TestRouteCommands` per platform (recorded
  commands), `TestFwmarkRules`.
- `internal/client`: routes installed and removed from the fake
  device and the fake route table, held peer contributes none,
  exit-node selection persisted, unavailable exit node removes the
  default route, status and schema.
- `cmd/thawr`: `client up` flags on a non-Linux OS exit 2, `client
  exit-node` against a fake socket, status rendering, `admin peer
  routes`.
- `tests/routes_test.go` (integration, Linux): criteria 1, 2, 3, 5, 6
  (to be written; the fake-device test `TestDaemonRoutes` covers the
  control-plane side of 1, 3, 5 and 6 until then).

## Out of scope

- Routers on macOS and Windows, and the exit-node kill switch (fail
  closed when the exit node is unavailable).
- DNS through the exit node; names outside `.thawr` keep using the
  host's resolvers.
- IPv6 prefixes (spec 015 extends the same tables and selectors).
- Phones: their tunnel ends at the hub, which does not forward to
  subnet routers in this spec.
- Signed route approvals under the lock: a route rides on the trust in
  the peer that carries it (pinned, or signed with the lock on); the
  approval itself is the server's word, like visibility.
- Failover between two routers of the same prefix, and route metrics.
- Opting out of routes on the client (`--accept-routes=false`): the
  policy decides, and a rule that grants a route is the opt-in.
