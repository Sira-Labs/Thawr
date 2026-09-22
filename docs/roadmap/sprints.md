# Sprint plan — weekly sprints, Sunday to Saturday

*Planned 2026-09-21. Sprints are one week because the build budget
resets every Saturday. Sprints 1–3 in `TASKS.md` were spec batches
landed in the first ten days; from sprint 4 on a sprint is a calendar
week. A sprint's stories are ordered by priority: when the budget
reaches ~90 % the remaining stories roll into the next sprint
unchanged, nothing is squeezed in. One spec per session, one PR per
spec, `@coderabbitai review` on the PR, merge by the owner, release
from a tag on `main`.*

Sizing rule of thumb from sprints 1–3: one session lands one spec
(control plane, client, CLI, tests, docs, review round), and a week
fits two specs of that size, or one spec that touches the data plane on
every platform (routes, IPv6, a new subcommand with service files) plus
its manual checklist. The manual checklists in `docs/TESTING.md` are
the owner's time on real hosts, not build budget, and gate a release,
not a merge. Priorities: **M** must (sprint fails without it), **S**
should, **C** could.

Definition of done for every story (from `CLAUDE.md`): `make test
lint` clean, unit tests for control-plane logic, the netns integration
suite compiling and skipping cleanly where it cannot run, docs touched
(spec, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` when a threat
row changes, `README.md` when a command is visible), the spec's entry
in `TASKS.md` with one line per non-obvious decision, a manual
checklist section in `docs/TESTING.md`, and, for user-facing stories,
a `client status` or CLI transcript in the PR.

## Milestones

| Milestone | Sprints | Exit criteria |
|---|---|---|
| **v0.1.0 — R1 core** | 4 (until 26 Sep 2026) | specs 001–012 on `main`; manual checklists 010–012 passed on the owner's hosts; Windows client enrolled, synced and torn down once; `v0.1.0` tagged with reproducible archives and the Homebrew formula |
| **R2 reach, release 0.2** | 5–8 (until 24 Oct 2026) | exit nodes and subnet routers, backup and restore, metrics, optional ACME, IPv6 overlay, separate relay nodes; `v0.2.0` |
| **R3 identity for agents, release 1.0** | 9–13 (until 28 Nov 2026) | OIDC login, workload enrolment with short-lived tokens and ephemeral peers, key TTL with automatic rotation under the lock, process-bound agent identity, lock and audit hardening; `v1.0.0` |

## Sprint 4 — 20 to 26 Sep 2026 (this week) — close R1

Goal: land what is open, plan, verify on real hosts, tag `v0.1.0`. No
new feature work.

| ID | Story | Prio | Done when |
|---|---|---|---|
| S4-1 | This roadmap and sprint plan merged, linked from the README and `TASKS.md`; GitHub milestones created | M | `docs/roadmap/` on `main`, six milestones on the repository |
| S4-2 | Manual checklists for specs 010, 011 and 012 run on the VPS, the Mac and the phone (owner); every deviation filed as an issue against the `v0.1.0` milestone | M | checklist sections ticked in the PR that closes them, issues filed |
| S4-3 | Fixes for what S4-2 finds, one PR per issue | M | issues closed, CI green |
| S4-4 | Windows client: enrol, `client status`, names via NRPT, `client down`, `client uninstall` on a Windows host; the checklist in `docs/TESTING.md` loses its "untested" note | S | checklist updated with the observed output |
| S4-5 | `CHANGELOG.md` with the 0.1.0 entry (one line per spec, the security notes from the threat model), linked from the release notes | S | file on `main` |
| S4-6 | `v0.1.0` tagged by the release workflow; archives verified with `SHA256SUMS`, Homebrew formula installs on the Mac | M | release published, `thawr version` prints 0.1.0 on all three hosts |
| S4-7 | Process decisions left open: keep or drop the `Claude-Session` commit trailer; `.coderabbit.yaml` to silence the docstring-coverage notice | C | decision noted in `CONTRIBUTING.md` or the file added |

## Sprint 5 — 27 Sep to 3 Oct — 013 exit nodes and subnet routers

Goal: a peer can carry traffic for addresses that are not its own,
and only when an admin approved it and the policy allows it.

| ID | Story | Prio | Done when |
|---|---|---|---|
| S5-1 | Spec 013 written: `client up --advertise-routes 10.1.0.0/24`, `--advertise-exit-node`, `--exit-node <name>`; approval by `thawr admin peer routes approve <name> <prefix>`; policy `routes:` selector gating who may use a route; threat-model row for a hijacked prefix (an approved route is part of the signed peer record under the lock) | M | spec merged with acceptance criteria and test names |
| S5-2 | Control plane: advertised and approved prefixes on peers (migration 0005), netmap carries approved routes as extra `AllowedIPs`, policy compiler gates them, audit actions `route.advertise`, `route.approve`, `route.revoke` | M | unit tests in `internal/control`, `internal/store`, `internal/api` |
| S5-3 | Client: install routes for approved prefixes, exit-node selection with the default route through the peer and the hub and server addresses excluded; router side enables forwarding and masquerade (Linux, nftables; userspace filter passes routed traffic) | M | fake-device tests; netns test: host behind a router pinged from a client, client's egress leaves through the exit node |
| S5-4 | CLI, REST and UI: `admin peer routes list`, `approve` and `revoke`, ROUTES line in `client status`, routes column in `admin peer show` and the peers table | S | transcript in the PR, schema updated |
| S5-5 | macOS and Windows: routes installed through the platform adapter (`route`, `netsh`), exit node on macOS documented as best effort until tested | S | manual checklist section for 013 |
| S5-6 | Docs: ARCHITECTURE §4.9 routes, README paragraph, `TASKS.md` entry | M | docs merged |

## Sprint 6 — 4 to 10 Oct — 014 operations

Goal: a server can be backed up, restored, watched, and given a
browser-trusted certificate, without anything leaving the host by
default.

| ID | Story | Prio | Done when |
|---|---|---|---|
| S6-1 | Spec 014 written: backup archive format (SQLite online backup, `server.key`, TLS files, config copy, manifest with version and checksums), restore preconditions, metrics catalogue, ACME mode and its config keys | M | spec merged |
| S6-2 | `thawr admin backup [--out file]` over the admin socket and `thawr server restore <file>` on a stopped server; refuses a newer schema; audit `backup.create` | M | store test restores a backup into a fresh temp dir and lists the same peers |
| S6-3 | Prometheus text endpoint on the admin listener (`/metrics`): peers online, netmap generation, relay sessions and bytes, STUN requests, audit rows, login failures; never a key or a name | M | handler test, sample scrape in the PR |
| S6-4 | ACME TLS mode: `tls: {mode: acme, email: ...}` using `golang.org/x/crypto/acme/autocert` (row in the dependency table); self-signed stays the default; clients keep pinning the fingerprint they enrolled with, so the spec says how a certificate change is announced | S | staging-CA test behind a build tag, manual checklist on the VPS |
| S6-5 | Docs: README "Operations" section, ARCHITECTURE §6 backup, TESTING checklist for 014 | M | docs merged |

## Sprint 7 — 11 to 17 Oct — 015 IPv6 overlay

Goal: every peer has an IPv6 address next to its IPv4 one and every
feature that knows about addresses knows about both.

| ID | Story | Prio | Done when |
|---|---|---|---|
| S7-1 | Spec 015 written: ULA prefix in config (`overlay.ipv6: fd00:...::/64`, generated at bootstrap when absent), allocator, migration filling `ipv6` for existing peers, hub address | M | spec merged |
| S7-2 | Control plane and store: dual allocation, netmap and QR export carrying both families, policy compiler emitting v6 rules | M | unit tests |
| S7-3 | Client and WireGuard adapters: v6 address and `AllowedIPs` on Linux, macOS and Windows; nftables and userspace filters for v6; resolver answers AAAA | M | fake-device tests; netns test pings v6 between two clients and through the hub |
| S7-4 | Status, admin CLI and UI show both addresses; `docs/status.schema.json` updated | S | golden files updated |
| S7-5 | Docs and threat model (no new exposure: v6 stays inside the tunnel) | M | docs merged |

## Sprint 8 — 18 to 24 Oct — 016 separate relay nodes, release 0.2

Goal: relays can run where the traffic is, and `v0.2.0` ships.

| ID | Story | Prio | Done when |
|---|---|---|---|
| S8-1 | Spec 016 written: `thawr relay --server https://... --token ...` with a relay token kind, relay registration and heartbeat, relay list in the netmap ordered by measured latency, the server's own relay first when nothing else answers | M | spec merged |
| S8-2 | Server: relay registry, token kind `relay`, netmap field, admin `relay list`, audit | M | unit tests |
| S8-3 | Relay binary path: `thawr relay` subcommand reusing `internal/relay` with the server's visibility check answered over gRPC; `relay install` service files | M | netns test: two symmetric NATs talk through a standalone relay |
| S8-4 | Client: relay candidates from the netmap, failover between relays, status shows which relay | M | fake-device tests, status transcript |
| S8-5 | `CHANGELOG.md` 0.2.0, manual checklists 013–016 on the owner's hosts, `v0.2.0` tagged | M | release published |

## Sprint 9 — 25 to 31 Oct — 017 OIDC provider

Goal: a person logs in to the admin UI with the organisation's
identity provider and the server keeps working when that provider does
not (ADR 0006).

| ID | Story | Prio | Done when |
|---|---|---|---|
| S9-1 | Spec 017 written: `auth.oidc` config (issuer, client id, secret via `_file`, claim mapping), authorization-code flow with PKCE on the admin UI, subject-to-user mapping with first-login creation, groups claim usable in the policy file, local login always available | M | spec merged, ADR 0006 unchanged |
| S9-2 | Provider interface in `internal/control` with a discovery-based implementation on `github.com/coreos/go-oidc` (Apache-2.0, pure Go; dependency table row) and a fake provider for tests | M | unit tests with the fake |
| S9-3 | REST and UI: login button, callback route, session creation, CSRF unchanged; audit `login` rows carry the provider | M | handler tests, screenshot in the PR |
| S9-4 | Policy: `groups:` entries may name `oidc:<group>`; compiler resolves through the mapping table | S | policy tests |
| S9-5 | Docs: README "Identity" paragraph, ARCHITECTURE §3, TESTING checklist against a test realm | M | docs merged |

## Sprint 10 — 1 to 7 Nov — 018 workload enrolment

Goal: a CI job or an orchestrator enrols an agent without a person
and the agent goes away when its job does.

| ID | Story | Prio | Done when |
|---|---|---|---|
| S10-1 | Spec 018 written: service accounts, API tokens (scoped, hashed, expiring, created and revoked by an admin), `POST /api/v1/tokens` with a TTL and `kind: agent`, ephemeral peers (`--ephemeral`, deleted after `offline_ttl`), audit rows naming the service account | M | spec merged |
| S10-2 | Store and control: `service_accounts`, `api_tokens` (migration), token scopes `tokens:create`, `peers:read`; enrolment token TTL down to one minute; ephemeral flag and reaper | M | unit tests with injected clocks |
| S10-3 | REST: bearer API tokens next to browser sessions, scope checks on every route; `admin service-account create`, `list` and `revoke` | M | handler tests: wrong scope is 403, expired is 401 |
| S10-4 | Client: `client up --ephemeral`; status says so; `client down` on an ephemeral peer deletes it | S | fake-device tests |
| S10-5 | Example: a GitHub Actions job that mints a token and enrols a runner as `kind: agent` (docs only, no network access in CI) | C | `docs/examples/ci-agent.md` |

## Sprint 11 — 8 to 14 Nov — 019 short-lived peer keys

Goal: keys expire and rotate on their own, and the lock still decides
who is on the network.

| ID | Story | Prio | Done when |
|---|---|---|---|
| S11-1 | Design note first: automatic rotation under the lock. Candidate: a signer issues a bounded delegation (peer id, lock key, not-after) that lets that peer's own rotations count as signed until it expires; the spec decides and the threat model gets the row | M | note merged as part of spec 019 |
| S11-2 | Spec 019 written: `key_ttl` per kind in config, server refuses expired keys from the netmap and marks the peer `key expired`, client rotates at 80 % of the TTL, delegation format if S11-1 chose it | M | spec merged |
| S11-3 | Control plane: key issued-at and expiry on peers, netmap omits expired keys, audit `key.expire` | M | unit tests with injected clocks |
| S11-4 | Client: scheduled rotation, self-signing on signers, delegated signing where granted, status shows `key expires in` | M | fake-device tests: a rotation lands before expiry and needs no `trust` |
| S11-5 | Docs, TESTING checklist (watch one rotation on the Mac) | M | docs merged |

## Sprint 12 — 15 to 21 Nov — 020 process-bound agent identity

Goal: an identity belongs to a process, not to the host it runs on.
Research first; implementation only as far as the design carries.

| ID | Story | Prio | Done when |
|---|---|---|---|
| S12-1 | Research note: how SPIFFE workload attestation maps onto a WireGuard peer per process; options are a per-process network namespace with its own `thawr0`, or one interface with a per-process source port filter; what Linux, macOS and Windows each allow | M | `docs/research/01-process-identity.md` |
| S12-2 | Spec 020 written from the note: `thawr client agent run -- <cmd>` that attests the child (uid, pid, cgroup or container id), enrols it with a short-lived token from a service account, gives it its own key and tears it down on exit | M | spec merged |
| S12-3 | Linux implementation: namespace path, policy gating by `kind: agent` and owner, audit naming the agent | S | netns test: a process reaches only what its policy allows while the host user reaches nothing extra |
| S12-4 | macOS and Windows: documented as not supported in this release, with the reason | S | ARCHITECTURE §9 row |

## Sprint 13 — 22 to 28 Nov — 021 lock and audit hardening, release 1.0

Goal: the lock can be managed without turning it off, the audit log
can leave the host, and `v1.0.0` ships.

| ID | Story | Prio | Done when |
|---|---|---|---|
| S13-1 | `lock remove-signer <name>` and rotation of a lock key (a record signed by the old key that names the new one), optional quorum (`lock quorum 2`) with the acceptance rule in `internal/lock` | M | golden-byte tests, netns test removes a signer without a disable |
| S13-2 | Audit forwarding: syslog (RFC 5424 over TCP or a Unix socket) and webhook with retry; hash-chained rows with `admin audit verify` | M | store test detects a modified row, handler test for the webhook |
| S13-3 | Documentation pass: upgrade guide 0.x to 1.0, config reference generated from the defaults, threat model rows revisited | M | docs merged |
| S13-4 | `CHANGELOG.md` 1.0.0, manual checklists 017–021 on the owner's hosts, `v1.0.0` tagged | M | release published |

## Working agreement

- Sunday: the sprint's stories in priority order, must-haves first;
  one spec per session with plan mode, as `CLAUDE.md` says.
- Every push runs CI; every PR gets `@coderabbitai review` (the repo is
  below the star threshold for automatic reviews); findings are fixed
  before the owner merges. Releases are tags on `main`.
- Budget check at ~70 % and ~90 %: at 70 % stop starting stories that
  need a new spec; at 90 % stop, push, write the sprint's line in the
  progress log of `docs/roadmap/roadmap.md`, and roll the rest forward.
- Rolled-over stories keep their ID and move to the top of the next
  sprint. Manual checklists that the owner has not run yet stay open in
  `docs/TESTING.md` and block the release, never the merge.
