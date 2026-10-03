# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/). Until 1.0,
minor versions may change config keys and the admin API. The release
workflow uses the section for the tagged version as the release notes
when one exists, and GitHub's generated notes otherwise.

## [Unreleased]

### Added

- IPv6 overlay (spec 015): every peer gets an IPv6 address next to its
  IPv4 one, the IPv4 address in the last 32 bits of a ULA `/64` the
  server generates once and keeps (`overlay.ipv6` to choose it; a
  changed prefix refuses to start). Clients say they carry IPv6 in
  `Enroll` and `Sync`, and only then get IPv6 addresses, `/128`s and
  IPv6 filter rules, so clients from before 015 keep an unchanged
  IPv4 netmap. Kernel and userspace filters match IPv6 (ICMPv6 errors
  and neighbour discovery always pass), names answer AAAA and
  `ip6.arpa`, `client status` and the admin views show both addresses,
  the phone config carries both, and exit nodes carry `::/0` with
  NAT66. Linux hosts that enable IPv6 forwarding (the hub, routers)
  move `accept_ra=1` interfaces to `2` first and restore both on stop.

- `thawr admin backup` and `thawr server restore` (spec 014): one
  archive with the database (consistent `VACUUM INTO` snapshot), the
  server's WireGuard key, the pinned TLS certificate, the ACME cache
  and copies of config and policy, with a manifest of SHA-256 sums;
  offered on the admin socket only and written 0600. Restore verifies
  the archive first, refuses a running server, a newer schema and a
  non-empty `data_dir` (`--force` moves it aside), migrates an older
  database, and keeps every client's pin valid.
- The server locks `data_dir` (`thawr.lock`): a second server on the
  same directory exits before it opens the database.
- `tls.mode: acme` (spec 014): a browser-trusted certificate from
  Let's Encrypt (or `tls.acme_directory`) for the server's domain,
  validated over the HTTPS port (TLS-ALPN-01, no port 80) and renewed
  on its own, while clients keep the pinned self-signed certificate:
  every client now asks for it by the name `thawr-pinned.invalid`, and
  only the domain is answered with the ACME one. Startup and `server
  --check` warn while `min_client_version` is below 0.2 (older clients
  dialling the domain would fail their pin) or `listen.https` is not
  on port 443.
- Prometheus metrics (spec 014) on the admin socket at `/metrics`, and
  on an opt-in plain-HTTP listener (`metrics.listen`): peers by kind and
  online, netmap generation, relay and STUN counters, failed logins,
  audit rows, uptime. Counts only, never a name, address or key; no
  new dependency.

### Fixed

- Paths: a device with no traffic of its own neither punched back nor
  joined the relay, so two devices behind symmetric NATs could reach
  each other only when both started talking (specs 004, 005). The
  server now tells a device when a peer is trying to reach it, and it
  probes back at once; the first handshake through a new relay
  connection is no longer dropped either. Two symmetric NATs now
  exchange the first echo through the relay within seconds.
- Product page: the Windows downloads pass `-UseBasicParsing`, so Windows PowerShell 5.1 with
  the December 2025 update no longer asks for confirmation.
- Product page: the install commands stop when a download fails or the checksum does not
  match. They check the `SHA256SUMS` line whose file name is exactly the archive; Windows runs
  in one `try` with `-ErrorAction Stop`, and Linux and macOS chain every step with `&&`. A Mac
  whose CPU is unknown gets no preselected architecture, and a newer release replaces the
  page's links only when it has every archive, `SHA256SUMS` and `thawr.rb`.
- Windows: saving the client state (an exit-node choice, a rename)
  could fail with "Access is denied" while another process, typically
  a virus scanner, briefly held the previous `state.json` open. The
  replace is now retried for up to two seconds.

## [0.1.0] - unreleased

Ships once the manual checklists for specs 010–013 have passed on real
hosts (`docs/roadmap/sprints.md`, sprint 4); the tag replaces
"unreleased" with the date. Pre-releases `v0.1.0-rc1`, `rc2` and `rc3`
(5 Sep 2026) carried specs 001–009.

### Added

- One binary `thawr` with the subcommands `server`, `client`, `admin`
  and `version`; Go, no CGO, reproducible builds (spec 001).
- Server bootstrap from a single YAML file where `public_addr` is the
  only required key: SQLite with embedded migrations, WireGuard and TLS
  key generation, hub interface, one TLS listener for gRPC, REST and the
  embedded admin UI, `--check`, clean shutdown (spec 001).
- Local users with argon2id passwords, one-time enrollment tokens, the
  peer registry with overlay IP allocation, admin CLI over a local
  socket, REST API and admin UI, `client up` with TLS fingerprint
  pinning (spec 002).
- Key distribution: netmap sync over a gRPC stream, kernel WireGuard
  through `wgctrl` or `wireguard-go` in process, client daemon with a
  cached netmap, local socket API, `client down` and `rotate-key`
  (spec 003).
- Direct connectivity through NAT: STUN built into the server, UDP hole
  punching through WireGuard handshakes, candidate ordering and a path
  state machine, `client ping` (spec 004).
- Relay fallback built into the server over the HTTPS port (HTTP
  upgrade), forwarding opaque WireGuard packets between mutually
  visible peers, rate limits, automatic upgrade back to a direct path
  (spec 005).
- ACL policy in a YAML file the user keeps in git: default deny,
  selectors by name, kind, owner and tag, enforcement by key
  distribution and a receiver-side port filter (nftables with kernel
  WireGuard, a userspace filter otherwise), `admin policy check`,
  `reload` and `show`, policy page in the UI (spec 006).
- `client status` with a table, `--json` validated by
  `docs/status.schema.json`, `--watch`, exit codes, connection state,
  NAT type and drop counters; `admin peer show` and `--online`
  (spec 007).
- Mobile peers through the hub: `admin peer add-mobile` prints a
  one-time WireGuard QR code for the official app; the server keeps
  only the public key (spec 008).
- Release and install: reproducible archives with `SHA256SUMS`, a
  Homebrew formula per release, `server install` and `client install`
  registering systemd units, launchd plists or a Windows service,
  `uninstall` with `--purge`, `min_client_version`, server version in
  status (spec 009).
- Names: `<name>.thawr` served by every client from its netmap and by
  the hub for phones, registered with systemd-resolved, `/etc/hosts`,
  a macOS resolver file or a Windows NRPT rule and undone on
  `client down`; `--dns serve|off` (spec 010).
- Key pinning and audit log: every client pins the hub key and each
  peer's key on first sight and holds a changed key out of the tunnel,
  DNS and the filter until `client trust <name>`; every control-plane
  mutation lands in an audit table with actor and target (`admin
  audit`, `GET /api/v1/audit`, the UI) with a retention pruner
  (spec 011).
- Network lock: an Ed25519 lock key on a device the owner controls
  signs each peer record; the server stores and forwards signatures
  but never holds a signing key; a client with the lock on holds
  unsigned peers, accepts signed rotations without `trust`, pins the
  lock record and refuses records the signer set did not sign;
  `client lock init|status|sign|key|add-signer|disable`, `admin lock`,
  a SIGNED column, `client up --lock-signer <key>` for devices enrolled
  while the server may already be hostile (spec 012).
- Subnet routers and exit nodes: `client up --advertise-routes` and
  `--advertise-exit-node` (Linux), admin approval with `admin peer
  routes approve|revoke|list`, policy `dst` CIDRs outside the overlay
  and `internet`, routes installed through `thawr0`, `client exit-node
  <name>|off|status` with fwmark policy routing on Linux, forward and
  masquerade rules on the router, `Routes:` line in status (spec 013).
- CI on Linux, macOS and Windows with race tests, cross-builds for five
  targets, a reproducibility check of the archives and `govulncheck`;
  release workflow from a tag or by hand; Dependabot; issue and pull
  request templates.
- Documentation: vision, architecture, ADRs 0001–0006, threat model,
  testing guide with manual checklists per platform, one spec per
  feature, roadmap and weekly sprint plan.
- Product page on GitHub Pages (`site/`), redeployed after every
  successful release: `scripts/site-release.sh` points its download
  links, archive sizes and release-candidate note at the newest release
  (the note disappears for a stable one), and CI tests that rewrite
  against the current page.
- Auto-merge for every pull request (`automerge` workflow): it merges
  once the checks the branch rule on main requires have passed and its
  review conversations are resolved.

### Changed

- The repository moved to `Sira-Labs/Thawr` and the Go module path is
  now `github.com/sira-labs/thawr`; `go install` and imports must use
  the new path, the old one no longer resolves to this module.

### Fixed

- A second `thawr client up` on the same socket exits 2 with `already
  running` instead of taking the socket over and racing the first
  client for the WireGuard port; a stored listen port held by another
  process is replaced at start; the userspace adapter no longer rebinds
  its socket on every netmap (found on macOS with v0.1.0-rc4).
- A name the policy selects with `peer:<name>` can no longer change
  hands silently: `thawr admin peer rename` refuses such a peer unless
  `--force` is given, members can neither issue a token for such a name
  nor add a phone with it, and at enrolment only a token an admin
  issued for the name may take it; any other request gets a numbered
  name instead of that peer's grants (found in a review after
  v0.1.0-rc5). Schema version 6 records who issued a token.
- Renaming the exit node a device uses no longer drops the default
  route and sends internet traffic around the tunnel; the choice is
  kept by peer id, so a different peer that later takes the old name
  is not used either.
- A renamed device takes its new name: `client status`, its own
  `<name>.thawr`, state.json and log hints follow the netmap. Before,
  it kept the old name, and with the network lock on it could not
  rotate its key or run `lock init` (both signed the old name) and
  reported itself unsigned. `admin peer rename` says when the lock
  needs the peer signed again.
- `client status`, `client down` and `client up` run without the
  rights to open the client socket say so and suggest sudo (exit 2).
  Before, status reported a running client as "not running" (exit 3),
  and `up` failed later with a bare "permission denied" on state.json.
- `thawr client start` and `thawr client stop` drive the installed
  service. After `client down` the service stayed stopped until the
  next boot (launchd and systemd do not restart a clean exit) and only
  `launchctl kickstart` or `systemctl start` brought it back. `down`,
  `status` and the "already running" error now point there; the last
  no longer suggests `client uninstall`.
- Running `client install` again starts a stopped service instead of
  only reporting it as installed, and refuses flags that would rewrite
  the enrollment state under the running client (`--advertise-routes`
  used to change state.json and still print "already installed").
- `thawr admin` run away from the server says that it talks to the
  server's local socket and must run on the server host; a permission
  error on that socket suggests sudo. The README's admin examples now
  use sudo.
- `hub` can no longer be a peer name: it collides with `hub.thawr`, the
  server's address, so such a peer never resolved through the hub. A
  host called `hub` enrols as `hub-2`.
- "No such name" answers under `.thawr` carry the zone's SOA, so
  resolvers cache them for at most 30 s instead of a platform default
  of minutes; a peer enrolled right after a failed lookup resolves
  once that entry expires.
- `add-mobile` (CLI and UI) warns when the hub resolver has no upstream,
  which leaves the phone with only `.thawr` names while the tunnel is up.
- Windows: `thawr client down` on the installed service stuck. The
  process exited while the service control manager still saw it
  running, which counts as a crash, so the manager restarted it after
  2 s. The service now reports Stopped first, with a non-zero exit code
  only when the client or server failed; new installs restart on that
  code (existing ones: `client uninstall`, then install again).
- Windows: a service's output was lost, and the `logs:` hint printed
  `sc query`, which shows only its state. The server and client
  services now write to `%ProgramData%\Thawr\logs\<service>.log`
  (panics included), and the hint follows that file. The folder is
  secured like the state directory before the file is opened, and a
  planted link or second name is refused, so the service never writes
  through someone else's link; reading the log takes an elevated shell.

### Security

- Thawr implements no cryptography: WireGuard for the tunnel, the Go
  standard library and `golang.org/x/crypto` for hashing, passwords
  and Ed25519 signatures.
- Node secrets, enrollment tokens and passwords are stored hashed; logs
  and the audit log carry key fingerprints, never keys.
- Phone traffic terminates at the hub, so the server can read it
  (`docs/THREAT_MODEL.md`, T4); laptops and servers talk end to end.
- The network lock closes the compromised-server key-substitution
  threat once a device has pinned the lock record; the first record a
  device sees is trusted unless it was enrolled with `--lock-signer`.
- Windows: the client's control socket defaulted to
  `C:\var\run\thawr\client.sock`, and its state directory
  `%ProgramData%\Thawr` (with `node.key`) inherited an access list that
  lets every local user read, so another user could stop the client,
  rotate its key or read the private key. The socket now defaults to
  `%ProgramData%\Thawr\client.sock`; the state directory and the socket
  admit only SYSTEM, Administrators and the owner, and Administrators
  become the owner of the state directory, so one a standard user
  created beforehand is taken back. Existing services keep the old
  socket until `client uninstall` and install again.
- Windows server: `data_dir` (default `C:\var\lib\thawr`, holding the
  server keys and the database) and the admin socket inherited an
  access list that lets every local user read, and the admin socket
  grants full admin. The server now makes Administrators the owner of
  `data_dir` on every start and limits it and the admin socket to
  SYSTEM, Administrators and the owner.

[0.1.0]: https://github.com/Sira-Labs/Thawr/compare/v0.1.0-rc3...main
