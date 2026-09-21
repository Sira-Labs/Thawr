# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/). Until 1.0,
minor versions may change config keys and the admin API. The release
workflow uses the section for the tagged version as the release notes
when one exists, and GitHub's generated notes otherwise.

## [Unreleased]

Everything below ships as `v0.1.0` once the manual checklists for
specs 010–012 have passed on real hosts (`docs/roadmap/sprints.md`,
sprint 4). Pre-releases `v0.1.0-rc1`, `rc2` and `rc3` (5 Sep 2026)
carried specs 001–009.

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

[Unreleased]: https://github.com/thedatadudech/Thawr/commits/main
