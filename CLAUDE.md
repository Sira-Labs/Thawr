# CLAUDE.md — working agreement for Claude Code sessions on Thawr

Thawr is a self-hosted, WireGuard-based private network (mesh VPN / ZTNA).
One binary. No cloud. Works offline. Language: Go. License: Apache-2.0.

Read this file first in every session. Then read `docs/ARCHITECTURE.md`
and the one spec in `docs/specs/` the session is about. Do not read all
specs; only the one you implement plus any it references.

## Session protocol

1. One spec per session. The session prompt names it
   (`Implement docs/specs/NNN-name.md. Plan first.`).
2. Use plan mode. Present the plan, wait for approval, then implement.
3. Run `make test lint` before every commit. Both must be clean.
4. Commit with a semantic message (see below). One logical change per
   commit; a spec may take several commits.
5. Mark the spec done in `TASKS.md` and add one line per non-obvious
   decision under that spec's entry (these are the session notes).
   When a sprint closes, add its line to the progress log in
   `docs/roadmap/roadmap.md`; the sprint's stories are in
   `docs/roadmap/sprints.md`.
6. Do not start the next spec. Do not refactor code the spec does not touch.
7. Ask before deviating from any ADR in `docs/adr/` or any fixed decision
   in `docs/ARCHITECTURE.md`. If a spec contradicts an ADR, stop and ask.
8. Never commit debug code, `fmt.Println` debugging, or commented-out code.

## Commands

```
make build         # go build -o bin/thawr ./cmd/thawr
make test          # go test -race -count=1 ./...
make lint          # gofmt -l . ; go vet ./... ; golangci-lint run
make run-server    # go run ./cmd/thawr server --config config/server.example.yaml
make run-client    # go run ./cmd/thawr client up --server https://127.0.0.1:8443 --token $THAWR_TOKEN
                   # (enrols when needed, then runs the sync daemon; client status|ping|down|rotate-key talk to its socket)
make integration   # go test -race -tags integration ./tests/... (Linux, needs CAP_NET_ADMIN)
                   # thawr admin policy check|reload|show and admin peer list|show|add-mobile talk to the server over the admin socket
                   # client status exits 0 connected, 1 server unreachable, 2 usage, 3 not running
make release VERSION=vX.Y.Z   # scripts/release.sh: reproducible archives, SHA256SUMS, Homebrew formula in dist/
make release-verify           # builds two targets twice, fails unless byte-identical
                   # thawr server|client install|uninstall register the binary with systemd, launchd or the Windows SCM (root)
make proto         # regenerate gRPC/protobuf code (buf + plugins via go run, nothing to install)
```

Single package: `go test -race -run TestName ./internal/control/...`.
Toolchain: Go 1.26 or newer; `go.mod` pins the minimum. No CGO anywhere
(`CGO_ENABLED=0` must build the whole binary).

## Repository layout

```
cmd/thawr/          entry point, subcommands server | client | admin
internal/control/   peer registry, keys, enrollment, policy engine, netmap; path/ = candidate order + path state machine
internal/stun/      STUN codec (copied from Tailscale), client discovery, rate-limited server
internal/relay/     relay server and client-side relay proxy
internal/dns/       resolver for <name>.thawr (client and hub), forwarding, split-DNS registrars
internal/wg/        WireGuard adapter: kernel (wgctrl) and wireguard-go
internal/store/     SQLite persistence and embedded SQL migrations
internal/api/       gRPC (client<->server) and REST (admin UI) handlers
internal/config/    YAML loading, validation, defaults
internal/client/    device side: state dir, TLS pinning, enrollment, sync daemon, local socket API
internal/server/    composes the server: bootstrap order, readiness, reload, shutdown
internal/svc/       service manager adapters: systemd units, launchd plists, Windows services
web/                admin UI: plain HTML/JS, embedded via embed.FS
docs/               vision, architecture, ADRs, threat model, specs
tests/              integration tests (netns-based)
config/             example configs
scripts/            release.sh (reproducible archives); packaging/ holds the Homebrew formula template
```

## Fixed architecture decisions

Full detail and rationale in `docs/ARCHITECTURE.md` and `docs/adr/`.
These are not up for discussion inside an implementation session.

- Single binary `thawr` with subcommands `server`, `client`, `admin`
  (ADR 0005).
- Data plane is WireGuard only: kernel module via `wgctrl` where present,
  otherwise `wireguard-go`. No other tunnel protocol (ADR 0004).
- NAT traversal: STUN (built into the server) plus UDP hole punching via
  WireGuard handshakes; DERP-style relay built into the server binary as
  fallback. The relay forwards opaque WireGuard packets and never holds
  session keys.
- Control plane: gRPC between client and server, REST plus embedded HTML
  admin UI, all on one TLS listener. Admin CLI talks to the server over a
  local Unix socket (Windows: named pipe).
- Store: SQLite via `modernc.org/sqlite`, pure Go (ADR 0002). Migrations
  are numbered SQL files embedded in `internal/store`.
- Config: one YAML file. A server starts with `public_addr` alone; every
  other key has a default.
- Policy: YAML ACL file owned by the user (typically in their git repo).
  Default deny. Enforced by key distribution (visibility) and on the
  receiving peer (port filter).
- Identity: local users plus one-time enrollment tokens. OIDC is optional
  and pluggable, never required (ADR 0006).
- Every peer is a generic identity with `kind` in {human, server, agent}.
  Nothing may assume a peer is a person.
- Logging: `log/slog`, structured, key=value. Never log keys, tokens,
  secrets, or password hashes; log key fingerprints (first 8 hex chars of
  SHA-256) instead.

## Rules

1. Never implement cryptography. Use WireGuard for the tunnel, `crypto/*`
   and `golang.org/x/crypto` for hashing and password storage,
   `crypto/rand` for randomness. No hand-rolled key exchange, no custom
   framing that carries plaintext secrets.
2. Never log or print a private key, node secret, enrollment token secret,
   or password. Tests must not contain real keys either; generate them.
3. Zero hardcoded secrets. Secrets come from env vars or files with mode
   0600. Config values that are secrets accept `_file` variants.
4. Validate at every boundary: config on load, every gRPC/REST request,
   every token, every policy file. Reject, do not sanitize silently.
5. Errors are wrapped with `fmt.Errorf("...: %w", err)` and carry context
   (peer id, token id, file path). No blanket `recover`. No `panic` outside
   `main` and programmer-error guards.
6. Dependencies are injected through constructors (`New...(deps)`).
   No package-level mutable state, no `init()` that does work.
7. Exported identifiers have doc comments. Inline comments only where the
   logic is non-obvious. TODOs are written `TODO(YYYY-MM-DD): text`.
8. Unit tests for all control-plane logic (`internal/control`,
   `internal/store`, `internal/config`, `internal/api`). Table-driven
   where natural. Store tests open a SQLite file in `t.TempDir()`; the
   shared-cache in-memory DSN misbehaves under `database/sql` pooling.
9. Platform-specific code lives in `_linux.go`, `_darwin.go`,
   `_windows.go` files with a shared interface; the rest of the tree must
   compile and test on all three.
10. Adding a dependency requires: permissive license (Apache-2.0, MIT,
    BSD), pure Go, and a line in the dependency table in
    `docs/ARCHITECTURE.md`.
11. Semantic commits only: `feat:`, `fix:`, `refactor:`, `docs:`,
    `chore:`, `test:`. Scope in parentheses when useful:
    `feat(control): one-time enrollment tokens`.

## Code style

- `gofmt` and `goimports` formatting. `golangci-lint` config in
  `.golangci.yml` is the source of truth for enabled linters.
- Context first parameter on anything that does I/O.
- Interfaces are defined where they are consumed, kept small.
- Time is injected (`func() time.Time`) wherever expiry is checked, so
  tests do not sleep.
