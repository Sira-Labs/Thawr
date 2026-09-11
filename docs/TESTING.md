# Testing

## Automated

| Command | What runs | Where |
|---|---|---|
| `make test` | Unit tests with the race detector, fake WireGuard device, in-process gRPC/TLS | Every OS, CI matrix |
| `make lint` | gofmt, go vet, golangci-lint | Linux, CI |
| `make integration` | Network-namespace tests in `tests/`: server boot, two-client enrollment, encrypted ping, NAT traversal (restricted/restricted, full-cone/symmetric, symmetric/symmetric, same LAN; needs `nft`), relay over symmetric NATs, relay-to-direct upgrade (needs `conntrack`), relay throughput (needs `iperf3`), policy enforcement end to end (needs `nc`), a phone joining via `wg-quick` through the hub and the policy it is subject to (needs `wg-quick`, `nc`), the nftables ruleset listing (`internal/wg`, needs `nft`), server and client installed as systemd services with the real binary (skips unless systemd is PID 1 and no thawr service exists), `<name>.thawr` resolution through each client's resolver and through the hub from the phone (needs `wg-quick`; clients run with `--dns serve` so the host's resolver files are never touched), a rotated key held on the other client until `client trust` and the rotation in `admin audit`, the network lock end to end (`lock init` on one client, a third client held as `unsigned` on both until `lock sign`, an unsigned rotation held and a signed one applied without `trust`, `admin lock`, the SIGNED column, `lock.set` and `peer.sign` in the audit log, `lock disable`) | Linux, root, iproute2, nftables |
| `make release-verify` | Builds two targets twice and compares the archives; CI runs it on every push and before every release | Linux |

The integration tests use the real binary and the WireGuard adapter that
`wg.Open` selects on the host: the kernel module when it loads, else
`wireguard-go` on a TUN device. Run them on a Linux VM with:

```
sudo make integration
```

## Manual checklist for the WireGuard adapters

Run once per adapter when the adapter code changes. Record the result
in the pull request.

### Linux, kernel module (`backend=kernel`)

1. `modprobe wireguard`, then `thawr client up ...` as root.
2. `ip link show thawr0` exists, `ip addr` shows `100.64.x.y/10`.
3. `wg show thawr0` lists the hub and the visible peers with the same
   public keys as `thawr client status`.
4. `thawr client down` removes the interface.

### Linux, userspace (`backend=userspace`)

1. `rmmod wireguard` (or a host without the module) and repeat the steps
   above; `thawr client status` reports `"backend":"userspace"`.

### macOS (`utun`)

1. `sudo thawr client up ...` (the interface defaults to `utun` on macOS); the log shows the
   assigned `utunN`.
2. `ifconfig utunN` shows the overlay address; `netstat -rn` has a route
   for the overlay prefix over `utunN`.
3. `ping` a peer; `thawr client status` shows a handshake.

### Windows (untested as of spec 003)

1. Place `wintun.dll` next to `thawr.exe`, run an elevated shell.
2. `thawr client up --interface Thawr ...`; `netsh interface ipv4 show
   addresses Thawr` shows the overlay address.
3. `ping` a peer.

If a step fails, the adapter code for that platform in `internal/wg`
(`addr_<os>.go`) is the place to look.

## Manual checklist for NAT traversal (spec 004)

Two devices behind different home routers, server on a public host.

1. `thawr client status --json` on each device lists `nat.local` (a
   LAN address) and `nat.reflexive` (the router's public IP);
   `nat.type` is `cone` on ordinary routers.
2. The peer shows `idle` in the PATH column (`probes: 0` in JSON) until
   traffic flows.
3. `thawr client ping <peer>` returns `direct` within 10 s with the
   peer's public `ip:port`; `ping` over the overlay works and the other
   device shows `direct` as well.
4. On a symmetric NAT (many carrier-grade NATs) the status line reads
   `NAT: symmetric`; two such devices end at `unreachable` until the
   relay (spec 005).
5. Two devices on the same LAN pick the LAN address as the path
   endpoint even though both have reflexive candidates.
6. The admin UI's "Show" under a peer lists the paths it reported.

## Manual checklist for the relay (spec 005)

1. Put one device behind a symmetric NAT (a phone hotspot usually is
   one) and `thawr client ping <peer>`: the path line ends in `relay`,
   `thawr client status --json` shows `relay.connected: true`,
   `relay.peers: 1`, and `ping`/SSH over the overlay work.
2. `/api/v1/status` on the server counts `relay.sessions`, `frames` and
   `bytes` growing; with `relay.max_bytes_per_second` set low, `drops`
   grows and the transfer slows.
3. Restart the server: `status` shows `relay.connected` false, then true
   again within seconds; traffic resumes without `client down`.
4. Move the relayed device to an ordinary network: within about a
   minute the peer reads `direct` and `relay.peers` drops to 0; the
   relay connection closes five minutes later.
5. `curl -k https://server/relay` without a token answers 401; the
   server log never contains payload bytes.

## Manual checklist for the policy (spec 006)

1. Start with no policy file: `thawr client status` on every device
   lists no peers; `thawr admin policy show` reports the empty
   default-deny policy.
2. Write a rule opening one port from one user to another, run `thawr
   admin policy reload`: both devices list each other within 5 s, the
   destination's `status` shows `filter.rules: 1`.
3. `nc` to the allowed port connects; to another port it times out and
   `filter.drops` grows on the destination; a reply to a connection
   the destination opened itself passes.
4. With kernel WireGuard `nft list table inet thawr` shows the chain
   with policy drop and one rule per policy entry; with `wireguard-go`
   the same behaviour comes from the userspace filter.
5. `thawr admin policy check bad.yaml` names the rule index and field;
   a reload of a broken file answers with the errors and `show` still
   prints the previous hash.
6. A member cannot create a token carrying a tag that `tagOwners` does
   not grant them (403 in the UI); an admin always can.

## Manual checklist for the CLI (spec 007)

1. `thawr client status` on a connected device: the first line ends in
   `connected (netmap #N, Ns ago)`, the second names the backend,
   interface, listen port and NAT type, the table has one row per
   visible peer plus `hub`, and the exit code is 0.
2. `thawr client ping <peer>` on an idle peer prints `path: idle →
   direct <ip:port>` (or `relay`), three echo replies, and exits 0;
   `client status` afterwards shows the path, the handshake age and
   RX/TX. `--count 0` skips the echoes; an unknown peer exits 2.
3. `thawr client status --json | jq .` shows the document from
   `docs/status.schema.json`; it never contains `node_secret` or a
   private key.
4. `thawr client status --watch` redraws every 2 s and exits 0 on
   Ctrl-C.
5. Stop the server: within a minute the first line reads `cached netmap
   (server unreachable since HH:MM; attempt N, next in Ns)`, the peers
   keep their paths, and the exit code is 1. Stop the client: the exit
   code is 3.
6. `thawr admin peer list` shows STATE, LAST SEEN, PATHS, VERSION and
   OS for every peer and `--online` keeps the connected ones; `thawr
   admin peer show <name>` lists the candidates, the reported paths and
   the compiled filter rules of the policy.

## Manual checklist for mobile peers (spec 008)

1. `thawr admin peer add-mobile --owner alice --name alice-phone`
   prints the T4 warning, a QR code that fits the terminal and the
   config; the private key appears nowhere in the server log or in
   `thawr.db` (`grep`). `--out phone.conf` writes the file with mode
   0600 and prints no config; `--no-qr` prints no code.
2. Scan the QR with the official WireGuard app (or `wg-quick up` the
   file on a Linux box) and activate the tunnel: within a minute
   `thawr admin peer list` shows `alice-phone static online` with a
   last-seen age, and alice's laptop lists it as `via hub` in
   `client status`.
3. From the phone, open something alice's policy allows on one of her
   peers (ssh, a web page); a denied port on another peer times out and
   that peer's `client status` filter counts the drop; a peer alice may
   not see does not answer at all.
4. `thawr admin peer delete alice-phone`: the phone loses connectivity
   within a second; `add-mobile` again yields a different key and the
   old tunnel stays dead.
5. In the admin UI, "Add mobile peer" opens the QR once in a dialog;
   after "Close and discard" there is no way to see the config again.

## Manual checklist for release and install (spec 009)

1. Download a release archive and `SHA256SUMS`, `sha256sum -c
   SHA256SUMS --ignore-missing` passes; `thawr version` prints the tag,
   `go1.x`, the platform and the commit; `--json` has the same fields.
2. macOS: `sudo thawr server install --public-addr ...` or `sudo thawr
   client install --server ... --token ... --fingerprint ...` writes
   `/Library/LaunchDaemons/thawr-<role>.plist` and the service is
   running (`sudo launchctl print system/thawr-client` shows `state =
   running`; `tail -f /Library/Logs/Thawr/thawr-client.log`). Reboot:
   the service is running again and `thawr client status` exits 0.
   `sudo thawr client uninstall` stops it and keeps the enrollment;
   `--purge --yes` removes `/Library/Application Support/Thawr`.
3. Windows (untested as of spec 009): in an elevated shell
   `thawr client install --server ... --token ... --fingerprint ...`
   creates the `thawr-client` service (`sc query thawr-client` shows
   RUNNING) with `wintun.dll` next to `thawr.exe`; it survives a
   reboot; `thawr client uninstall` deletes it.
4. Linux without systemd (Alpine, containers): `install` exits 2 with
   a message; `thawr client up` in the foreground still works.
5. `install` as a normal user exits 2 with `run as root (sudo)`; a
   binary under the home directory is refused unless `--bin` names it.
6. Replace the binary with a newer release and restart the service:
   the server logs pending migrations, the client reconnects without
   re-enrolling, and a client running an older release shows
   `client update available` in `thawr client status`.

## Manual checklist for names (spec 010)

1. Linux with systemd-resolved: after `thawr client up`, `resolvectl
   status thawr0` lists the client's overlay address as DNS server with
   `~thawr` as routing domain; `getent hosts <peer>.thawr` answers;
   `client down` leaves `resolvectl status` without the entry.
2. Linux without systemd-resolved (Docker host, Alpine): `/etc/hosts`
   gains the `# thawr begin` … `# thawr end` block with one line per
   peer; every other line is byte-identical (`diff` against a copy);
   `client down` removes the block; `client status` says `DNS: .thawr
   via hosts`.
3. macOS: `scutil --dns` lists a resolver for domain `thawr` after
   `client up`; `ping <peer>.thawr` works; `/etc/resolver/thawr` is
   gone after `client down` or `client uninstall`.
4. Windows (untested as of spec 010): `Get-DnsClientNrptRule` shows
   the `.thawr` namespace after `client up`; `Resolve-DnsName
   <peer>.thawr` answers; the rule is gone after `client down`.
5. Phone: re-scan a QR from a server with `dns.enabled` (the default);
   the WireGuard app shows `100.64.0.1` under DNS; the browser opens
   `http://<peer>.thawr:<port>` and ordinary websites still load
   (their names resolve through the hub, which forwards only the DNS
   query to its upstreams; the traffic itself takes the phone's normal
   route); a peer the policy hides does not resolve.
6. `client status` shows `DNS: .thawr via <method>`; `--json`
   validates with the `dns` object; `--dns off` omits both.
7. `dig @<self ip> -x 100.64.0.1` answers `hub.thawr.`;
   `dig @<self ip> example.com` is REFUSED; the same against the hub
   address forwards.

## Manual checklist for key pinning and the audit log (spec 011)

1. Two devices see each other. `thawr client rotate-key` on the laptop
   prints the `thawr client trust <laptop>` reminder; within seconds the
   desktop's `client status` header says `1 key changed: thawr client
   trust <laptop>`, the laptop's row reads `key changed`, `ssh
   <laptop>.thawr` fails to resolve and `client ping <laptop>` reports
   an unknown peer.
2. `thawr client trust <laptop>` on the desktop prints `trusted <laptop>
   (<old fp> → <new fp>)`; the row returns to `direct` and the name
   resolves again. `pins.json` in the state dir is mode 0600 and carries
   the new key.
3. Restart the desktop client before trusting: the laptop is still held
   (the pins, not the cached netmap, decide).
4. Admin UI as admin: the "Audit log" section lists the rotation
   (`peer:<laptop>`, `peer.rotate_key`, fingerprint), the login, and
   every token or peer action; "Load older" pages back; as a member the
   section is absent and `GET /api/v1/audit` answers 403.
5. `thawr admin audit --since 1h` and `--action peer.rotate_key --json`
   show the same rows; none contains a token secret or a full key.
6. With `audit: {retention_days: 1}` and an entry older than a day
   (`sqlite3` on a copy, or wait), the next start logs `audit: pruned
   old entries`.

## Manual checklist for the network lock (spec 012)

1. Two devices see each other. `thawr client lock init` on the laptop
   prints `network lock enabled (generation 1)`, one `signed <name>
   (<fp>)` line for the hub, the laptop and the desktop, and asks you to
   compare the fingerprints: `thawr client status` on the desktop shows
   the same fingerprint for its own key. Both status headers now read
   `lock: on` (`lock: on (signer)` on the laptop); `pins.json` carries
   the record and `lock.key` exists on the laptop only, mode 0600.
2. Enrol a third device. Within seconds the desktop's header says `1
   unsigned: thawr client lock sign <new>`, the row reads `unsigned`,
   the name does not resolve, and `thawr client trust <new>` on the
   desktop is refused with the `lock sign` hint. The new device's own
   `client lock status` says it is unsigned and its log names the
   signer command.
3. `thawr client lock sign <new>` on the laptop; the desktop releases
   it and `client ping <new>` finds a path. `thawr admin lock` lists
   the signer and no unsigned peer; `admin peer list` shows `yes` in
   SIGNED; `admin audit --action peer.sign` has one row per signature
   with fingerprints only.
4. `thawr client rotate-key` on the laptop prints `key rotated and
   signed`; the desktop switches without any `trust`. `rotate-key` on
   the desktop is held as `unsigned` on the laptop until `lock sign
   --all` there.
5. `thawr client lock key` on the desktop prints its fingerprint; on
   the laptop `lock add-signer <desktop> <wrong fp>` is refused with
   "mismatch" and `lock add-signer <desktop> <that fp>` succeeds; the
   desktop's header shows `(signer)` and
   `lock disable` there turns the lock off everywhere (`lock: off`,
   `admin lock` says `disabled at generation N`). `lock init` on either
   signer turns it on again; a non-signer's `lock init` is refused.
6. Stop the server, edit `meta.lock_record` in `thawr.db` to a record
   signed by some other key (or delete it) and start again: every
   client keeps its pinned record, `client lock status` prints the
   warning, and nothing is released or held that was not before.
7. Enrol a fresh device with `--lock-signer <laptop fp>` (from `client
   lock status` on the laptop): it adopts the record. Enrol another
   with `--lock-signer 00000000`: `client lock status` there shows the
   first record refused, `client status` lists no hub and no peers,
   and nothing works until the person fixes the fingerprint (`down
   --forget`, enrol again). Restarting the first device with a
   different `--lock-signer` exits 2. `lock init` from a device owned
   by a member is refused by the server.
