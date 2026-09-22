# Roadmap

Effort assumes AI-assisted development: one spec per session, one
session lands one spec with its tests and docs (`CLAUDE.md`). Weekly
sprint breakdown with stories and dates: `docs/roadmap/sprints.md`.
Progress per spec and the decisions taken in each session stay in
`TASKS.md`; this file holds the phases, the exit criteria and one
progress line per sprint.

## R0 — Design (done, 2 Sep 2026)

- `docs/VISION.md`, `docs/ARCHITECTURE.md`, ADRs 0001–0006,
  `docs/THREAT_MODEL.md`, specs 001–008, `TASKS.md`, scaffold with CI on
  Linux, macOS and Windows.

## R1 — Core private network, release 0.1 (sprints 1–4)

Goal: one binary that runs the server, the client and the admin CLI;
devices enrol with a one-time token, reach each other directly through
NAT or over the relay built into the server, are governed by a YAML
policy in git, have names, pin the keys they saw first, and can be
locked so that only a key the owner holds vouches for a peer. Phones
join through the hub with the official WireGuard app.

Progress log:

- **2026-09-02** sprint 1: 001 server bootstrap (config, SQLite and
  migrations, keys, TLS, hub, listeners), 002 peer enrollment (local
  users with argon2id, one-time tokens, registry, admin CLI, REST and
  embedded UI, TLS fingerprint pinning), 003 key distribution (netmap
  sync over gRPC, kernel and userspace WireGuard adapters, client
  daemon with cached netmap). PRs #1–#5.
- **2026-09-03/04** sprint 2: 004 direct connectivity (STUN, hole
  punching, path state machine, `client ping`), 005 relay fallback
  (framed relay over the HTTPS port, per-peer proxies, upgrade to
  direct), 006 ACL policy (selectors, compiler, receiver-side filter
  with nftables or userspace, `admin policy`), 007 CLI status (status
  document, `--json`, `--watch`, `admin peer show`), 008 mobile QR
  export (static peers through the hub). PRs #6–#12.
- **2026-09-05/11** sprint 3: 009 release and install (reproducible
  archives, `SHA256SUMS`, Homebrew formula, systemd, launchd and Windows
  services, `v0.1.0-rc1`–`rc3`), 010 DNS names (`<name>.thawr` on every
  client and through the hub, split-DNS registrars), 011 key pinning
  and audit log (`client trust`, `admin audit`, retention), 012 network
  lock (Ed25519 lock key on a device, signed peer records, `unsigned`
  holds, `--lock-signer`). PRs #13–#26.
- **2026-09-20/26** sprint 4 (in progress): this roadmap and sprint
  plan, manual checklists 010–012 on the owner's hosts, `v0.1.0`.

Exit criteria: specs 001–012 implemented with unit tests and the netns
integration suite green on a Linux VM; the manual checklists in
`docs/TESTING.md` for specs 003–012 passed on a Linux VPS, a Mac and a
phone, and the Windows client at least enrolled, synced and torn down;
`v0.1.0` tagged from `main` with reproducible archives and the Homebrew
formula; no open CodeRabbit finding on `main`.

## R2 — Reach, release 0.2 (sprints 5–8)

Goal: the network reaches beyond the devices that run the client.
Every item here is a phase-2 candidate named in `TASKS.md` or
`docs/ARCHITECTURE.md` §9; none changes the fixed decisions in
`CLAUDE.md`.

- **013 Exit nodes and subnet routers**: a peer advertises prefixes,
  an admin approves them, the policy gates who may use them, a client
  routes a subnet or all of its internet traffic through the approved
  peer. Router side: forwarding and masquerade on Linux with nftables.
- **014 Operations**: `thawr admin backup` and `thawr server restore`
  (SQLite online backup plus keys and TLS in one archive), a Prometheus
  endpoint on the admin listener, optional ACME TLS mode with the
  self-signed certificate staying the default so nothing needs the
  internet.
- **015 IPv6 overlay**: a ULA prefix next to `100.64.0.0/10`, dual
  addresses on every peer, AAAA records, the filter and the QR export
  carrying both families (the schema already reserves `ipv6`).
- **016 Separate relay nodes**: `thawr relay` registers with the
  server and appears in the netmap as an additional relay; the relay
  inside the server stays the default so a single host still works.

Exit criteria: a host behind a subnet router is reachable from a
laptop; a laptop's internet traffic leaves through an exit node and
returns; every peer has an IPv6 address that resolves and pings; a
standalone relay carries traffic between two symmetric NATs; a backup
restored on a fresh host brings the same network back without
re-enrolling; metrics scraped; `v0.2.0` tagged.

## R3 — Identity for agents, release 1.0 (sprints 9–13)

Goal: the positioning in `docs/VISION.md` ("an identity layer for
agents, not an IPsec replacement") becomes product. Identity per
workload, issued and rotated automatically, with the lock still the
authority over who is on the network.

- **017 OIDC provider** (ADR 0006): login to the admin UI through an
  external provider, subject-to-user mapping, groups usable in the
  policy file; local users keep working when the provider is down.
- **018 Workload enrolment**: service accounts with scoped, hashed,
  expiring API tokens so CI or an orchestrator can mint one-time
  enrolment tokens with a TTL and `kind: agent`; ephemeral peers that
  disappear after being offline for a configured time.
- **019 Short-lived peer keys**: a key TTL per kind, the client rotates
  before expiry, the server refuses expired keys from the netmap; how
  automatic rotation coexists with the lock (a signer's delegation with
  a bounded lifetime) is the design question this spec answers first.
- **020 Process-bound agent identity**: a workload API on the client's
  local socket that hands a process its own peer identity after local
  attestation (uid, pid, cgroup or container id); research and spec
  first, implementation behind it.
- **021 Lock and audit hardening**: `lock remove-signer`, rotation of
  a lock key, optional quorum; audit forwarding to syslog or a webhook
  and hash-chained audit rows.

Exit criteria: an agent enrolled by a CI job with a ten-minute token
appears with `kind: agent`, rotates its key on schedule and is refused
once the key expires; a person logs in to the admin UI with OIDC while
another logs in with a local user during a provider outage; a signer is
removed and a lock key rotated without disabling the lock; the audit
log arrives at a syslog receiver; `v1.0.0` tagged with an upgrade guide.

## Not scheduled

Named in `docs/VISION.md` and `docs/THREAT_MODEL.md` as non-goals or out
of scope, and not on this roadmap: native mobile apps and end-to-end
encryption for phones, Layer 2, a hosted control plane, hardware-backed
keys and device posture, multi-tenant servers, traffic-analysis
resistance.
