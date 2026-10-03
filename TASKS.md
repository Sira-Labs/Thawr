# Thawr — Backlog

Status legend: `[ ]` open, `[~]` in progress, `[x]` done. One spec per
session; mark it here and add one line per non-obvious decision below the
entry. Phases, exit criteria and the progress log per sprint are in
`docs/roadmap/roadmap.md`; the weekly sprint plan with dated stories is
`docs/roadmap/sprints.md` (sprints 4 onward; sprints 1–3 below were spec
batches).

## Phase 0 — Documents

- [x] CLAUDE.md, docs/VISION.md, docs/ARCHITECTURE.md, ADRs 0001–0006,
      docs/THREAT_MODEL.md, specs 001–008, TASKS.md (this file)

## Phase 1 — Scaffold

- [x] `go.mod`, `Makefile`, `.gitignore`, `.golangci.yml`, `README.md`,
      `LICENSE` (Apache-2.0, replacing the initial MIT file), `NOTICE`,
      `.github/workflows/ci.yml` (build, lint, test on Linux, macOS,
      Windows), `config/server.example.yaml`, `doc.go` in every package.
      `make build lint test` green. Commit `chore: initial scaffold`.
      - `make test` runs with `CGO_ENABLED=1` because the race runtime
        needs cgo; `make build` and CI cross-builds stay `CGO_ENABLED=0`.
      - `cmd/thawr` already wires cobra with `server`, `client`, `admin`
        and `version`; the first three return "not implemented" until
        their specs land.
- [x] `.github/workflows/ci.yml`: lint, race tests on three OSes,
      CGO-free cross-builds, govulncheck.

## Sprint 1 — control plane core

- [x] **001 Server bootstrap** — `docs/specs/001-server-bootstrap.md`
      Config load + defaults + validation, SQLite + migrations, key and
      TLS generation, hub interface, listeners, `--check`, clean
      shutdown, netns boot test.
      - New package `internal/server` holds the bootstrap; `cmd/thawr`
        only parses flags and signals.
      - Userspace WireGuard is configured through wireguard-go's
        in-process IPC (`IpcSet`), not a UAPI socket; the kernel adapter
        uses wgctrl. Windows returns `ErrPlatformUnsupported` until 003.
      - Policy loading is syntax-only (version 1, accept rules, known
        keys); spec 006 extends `policy.Load` in place.
      - STUN sockets are bound and drained; `/relay` answers 501.
      - Store tests use a temp-file DB, not the in-memory DSN.
      - `go.mod` requires Go 1.25 (pulled in by modernc sqlite and
        wireguard-go); CI uses `go-version-file`, so it follows.
      - `TestMigrateFromV1` waits for a second migration to exist.
      - The netns integration test skips without root and iproute2; it
        did not run in the development container (no `ip` binary). The
        real binary was booted manually there with userspace WireGuard
        and verified: files and modes, status over the socket, SIGTERM
        exit 0.
- [x] **002 Peer enrollment** — `docs/specs/002-peer-enrollment.md`
      Users (argon2id), one-time tokens, `Enroll` RPC, IP allocator,
      peer registry, admin CLI + REST + UI list/create, `client up`
      with fingerprint pinning.
      - New package `internal/client` (state dir, pinning, Enroll);
        `cmd/thawr` stays flags only.
      - gRPC and REST share the HTTPS listener via `api.Combine`
        (`grpc.Server.ServeHTTP` on HTTP/2 `application/grpc`).
      - Protobuf generated with buf and the Go plugins through `go run`
        at pinned versions; generated code is committed.
      - Browser sessions are in memory (12 h); the CSRF token travels in
        the login and `/me` responses, not a cookie, so the only cookie
        is HttpOnly. The admin socket acts as the local admin.
      - Login limiter: 10 failures per user per 15 min, then exponential
        backoff; Enroll: 10 attempts per minute per remote IP.
      - `client up` probes the server certificate and compares it with
        `--fingerprint` before sending anything; `--accept-fingerprint`
        is the explicit trust-on-first-use path. It exits after
        enrolling; the daemon is spec 003.
      - `min_client_version` compares MAJOR.MINOR; non-numeric versions
        (`dev`, git describe) are accepted.
      - REST addresses peers by name (`/peers/{name}`) because names are
        unique and what the CLI uses.
      - `go.mod` is on Go 1.26 (pulled in by grpc / golang.org/x);
        golangci-lint moved to v2.13.2 for the same reason.
      - The two-client netns integration test skips without root and
        iproute2 (not run in the development container); the CLI flow
        was exercised manually against the real binary instead.
- [x] **003 Key distribution** — `docs/specs/003-key-distribution.md`
      Netmap builder, `Sync` stream, endpoint table, `wg.Device`
      kernel + userspace adapters, client daemon with cached netmap,
      canonical integration test `TestEncryptedPingTwoClients`.
      - Visibility until spec 006: same non-empty owner, behind
        `control.Visibility`. Static peers appear as hub allowed IPs.
      - The server always sends a full netmap on connect; the netmap
        generation is the hub's in-memory sequence (persisted generation
        plus endpoint/presence changes), bumped at change time and
        delivered after a 200 ms coalesce.
      - The client replaces the whole peer set per netmap
        (`wg.Device.Configure` with ReplacePeers) instead of diffing.
      - Client address carries the overlay prefix length (on-link route);
        the listen port is random once and persisted in `state.json`.
      - Endpoint reports carry local interface addresses only; the
        client uses a peer's first candidate until spec 004's path state
        machine. The hub interface holds every registered peer.
      - Presence: online while a `Sync` stream is open plus 90 s grace,
        swept every 5 s; keepalive netmaps every 30 s.
      - Windows address setup uses `netsh` (compile-checked, untested;
        `docs/TESTING.md`). The client socket is a Unix socket on every
        platform.
      - gRPC shutdown is bounded (graceful for 2.5 s, then forced)
        because open Sync streams never end on their own.
      - wireguard-go's Errorf maps to warnings; "no known endpoint" to
        debug.
      - Verified on this box with the real binary: server plus two
        userspace-WireGuard clients on one host completed handshakes with
        the hub and each other, deletion emptied the other client's peer
        list within 2 s, key rotation and `down --forget` worked. The
        netns ping test skips here (no `ip` binary).

## Sprint 2 — connectivity, policy, UX

- [x] **004 Direct connectivity** — `docs/specs/004-direct-connectivity.md`
      STUN server + client, candidate ordering, path state machine, hole
      punching via WireGuard handshakes, NAT netns tests.
      - `internal/stun` is the Tailscale codec (BSD-3, D2) with Thawr's
        own SOFTWARE tag; the server answers only Thawr clients, 20 req/s
        per source IP.
      - STUN from the WireGuard port only works with `wireguard-go` (a
        `conn.Bind` wrapper); the kernel module's socket cannot be shared
        (bound without SO_REUSEADDR/SO_REUSEPORT), so kernel clients STUN
        from an ephemeral socket (public IP + symmetric verdict, port
        assumed preserved) and the server adds the hub-observed mapping
        of each peer as a reflexive candidate (`EndpointTable.SetObserved`).
      - `wg.Device.Configure` now diffs peers instead of replacing them
        (replace_peers drops every session on both kernel and
        wireguard-go); `SetPeer`/`RemovePeer` added. A probe removes and
        re-adds the peer so each 2 s window gets a fresh handshake
        initiation (WireGuard otherwise retries every 5 s).
      - Netmaps set no mesh-peer endpoint; the prober owns it. Idle peers
        point at a per-peer loopback sink socket that reveals traffic
        intent without transmitting (the same mechanism spec 005's relay
        proxy uses).
      - The probe trigger is one UDP datagram to the peer's overlay
        address on port 9, bound to the WireGuard interface
        (SO_BINDTODEVICE / IP_BOUND_IF), not an ICMP echo: no raw socket,
        same handshake effect.
      - Candidate kinds travel in the client netmap cache
        (`endpoints: [{addr, kind}]`); an old cache is ignored with a
        warning. Local candidates inside the overlay and loopback
        reflexive mappings are dropped before reporting.
      - `POST /ping/{name}` and `thawr client ping <peer>` exist now in a
        minimal JSON form; spec 007 formats them. Peer detail in the admin
        API and UI lists reported paths.
      - Linux masquerade is port-restricted, so the cone/symmetric case
        needs a full-cone NAT (catch-all DNAT) in `tests/nat_test.go`; a
        port-restricted cone facing a symmetric NAT cannot be punched
        without port prediction (out of scope).
      - Verified on this box with the real binary: STUN through the
        wireguard-go bind, idle peers with zero probes, `client ping`
        went probing to direct in 0.3 s, the other side followed by
        roaming, the server showed the path; no secrets in logs. The
        netns NAT tests skip here (no `ip`, no `nft`).
- [x] **005 Relay fallback** — `docs/specs/005-relay-fallback.md`
      Frame protocol, relay server with visibility check, client proxy
      sockets, relay→direct upgrade.
      - Re-probing from `relay` tries one candidate per 60 s (the next in
        turn) and returns to the relay after its 2 s window, so a failed
        retry costs at most one window of loss; a candidate change still
        starts a full simultaneous round. Switching the endpoint without
        a re-add and watching rx was rejected: roaming on both sides makes
        the endpoints ping-pong between proxy and candidate.
      - Loopback endpoints from `Stats` (sink or relay proxy) are masked
        before stepping the machine, so a rekey through the relay never
        looks like a direct handshake.
      - The relay checks the first payload byte for a WireGuard message
        type on both ends; the server drops and counts anything else.
      - The relay dial forces HTTP/1.1 (Go's server hijacks only there);
        gRPC stays on h2. The enrollment state stores the server as
        host:port, which `relay.Dial` accepts.
      - Visibility for the relay is `control.KeyVisibility` (peers by
        public key, cached per netmap generation); the registry-follow
        loop also prunes sessions of deleted peers.
      - `relay.max_bytes_per_second` is a per-session token bucket with a
        one-second burst; queue overflow and violations are counted and
        all counters sit under `relay` in `/api/v1/status`.
      - The relay connection opens on the first proxy and closes after
        5 min without one; a proxy lives 10 s past its release.
      - Verified on this box with the real binary: `/relay` answers 401
        without or with a wrong secret and 101 with the node secret, the
        status endpoint carries the relay counters, two on-host clients
        still reach `direct`, no secrets or payload bytes in logs. The
        netns relay tests skip here (no `ip`, `nft`, `conntrack`, `iperf3`).
- [x] **006 ACL policy** — `docs/specs/006-acl-policy.md`
      Policy parse/validate/compile, visibility, nftables filter,
      userspace filter, hub-side filter, `admin policy` commands.
      - Compilation is bitset based: one (rule, dst entry) pair holds a
        source and a destination bitset over the peer list; `self` is
        evaluated per pair by owner. 500 peers and 50 rules compile in
        about 25 ms (`BenchmarkCompile`).
      - Group selectors resolve to every peer owned by a member, so a
        server enrolled by an admin reaches whatever the admin may.
      - Unknown users and groups are validation errors; unknown tags and
        peers warnings. `thawr server --check` validates syntax only (no
        data dir); reload and check on the running server validate
        against the registry.
      - The compiled policy is cached per (policy hash, persisted
        generation), not the hub's in-memory sequence, which also moves
        on endpoint reports.
      - nftables: base chains cannot bind to one device on the input
        hook, so the chain has policy drop and a first rule `iifname !=
        <overlay iface> accept`; the hub uses the forward hook with
        `oifname`. `SetFilter` rebuilds the table in one batch.
      - Userspace filter: `tun.Device` wrapper; only inbound (device to
        TUN) is filtered, outbound records flows. An `any` rule lets ICMP
        through only when it opens every port.
      - `Filterable` is an optional device interface; the fake records
        the sets. A policy reload bumps the persisted generation so every
        Sync stream resends the map.
      - `github.com/google/nftables` v0.3.0 added (Apache-2.0, pure Go,
        Linux-only files); it pulled `mdlayher/netlink` to a newer
        pre-release.
      - Tests from earlier specs that assumed same-owner visibility now
        write an explicit `self` policy.
      - Verified on this box with the real binary (userspace WireGuard):
        no policy file gives an empty default-deny policy and no visible
        peers; `admin policy reload` made alice-box and bob-box visible
        within a second with one filter rule on bob; `client ping`
        reached direct while bob's filter dropped the trigger packet
        (drops=1); `admin policy check` rejected a broken file naming
        `acls[0].dst[0]` with exit 2; an invalid reload kept the previous
        hash; a member creating a `tag:prod` token got 403. nftables
        cannot run here (no CAP_NET_ADMIN); the netns policy test and the
        nftables ruleset test skip and need a Linux VM.
- [x] **007 CLI status** — `docs/specs/007-cli-status.md`
      Status document on the local socket with connection state, NAT
      type, typed candidates and a five-minute drop window; `client
      status` table, `--json` (schema-validated), `--watch`; `client
      ping` with ICMP and path changes; `admin peer list/show` with
      version, OS, paths, candidates and the compiled filter; exit codes.
      - The daemon serves the spec's nested document directly and the
        CLI renders it, so there is one shape and one schema
        (`docs/status.schema.json`, validated in `cmd/thawr` tests with
        `santhosh-tekuri/jsonschema`, tests only). The flat spec 003
        shape is gone; the netns tests moved to `--json` and the new
        field names.
      - Owner names and the receiver's kind travel in the netmap
        (`NetPeer.owner`, `SelfInfo.kind`); the builder resolves owners
        from the user table once per build.
      - `server.state` is `connected`, `reconnecting` (no netmap) or
        `cached` (netmap present, server unreachable); the daemon tracks
        attempt, next retry and unreachable-since. `nat.type` is derived
        from STUN (`symmetric`, `none`, `cone`, `unknown`); on this box
        STUN maps to loopback, which discovery drops, so it reads
        `unknown` here.
      - A peer's `path` reads `offline` when the server reports it
        offline and the prober is idle or unreachable; a direct or relay
        path outlives the server's presence verdict. The hub row is
        `direct <endpoint>` while its handshake is under 3 min old.
      - `filter.dropped_5m` samples the device's drop counter on the
        path loop's ticks (at most once per 5 s) and subtracts the
        sample from five minutes ago; a counter reset reads 0.
      - Client version and OS are persisted (migration 0002,
        `client_version`, `os` as `linux/amd64`); sync refreshes the
        version. `GET /peers/{name}` gained `endpoints`, `symmetric`,
        `filter` and every peer view a `path_summary`.
      - `client ping` = daemon probe + system `ping -c N` (`-n` on
        Windows) with the path polled every 200 ms in between; `--count
        0` skips ICMP for scripts and tests. Exit 0 needs a usable path
        (direct or relay) and, with echoes, at least one reply.
      - The spec's Windows named pipe is not implemented: the Unix
        socket on every platform is the shipped decision (spec 003
        notes, ARCHITECTURE §5). Unix sockets are chgrp'd to `thawr`
        when the group exists.
      - Usage errors exit 2 through a root flag-error func and
        `usageArgs`; golden output lives in `cmd/thawr/testdata` and is
        regenerated with `THAWR_UPDATE_GOLDEN=1`.
      - Verified on this box with the real binary (userspace WireGuard,
        server + two clients): `client status` showed the connected
        line, both peers and the hub; `client ping bob-box` printed
        `path: idle → direct 192.0.2.2:56213`, three echo replies and
        exit 0; both sides then showed `direct` with handshake age and
        RX/TX; `--json` had no secrets; `--watch` redrew twice in 3 s;
        `admin peer list` showed `1 direct`, version and `linux/amd64`;
        `admin peer show bob-box` listed the candidate, the reported
        path and alice's rule; unknown peer and `--bogus` exited 2;
        stopping the server gave `cached netmap (server unreachable
        since 11:00; attempt 2 ...)` with exit 1; stopping the client
        gave exit 3. No panics or races in the logs. The netns tests
        still skip here (no CAP_NET_ADMIN).
- [x] **008 Mobile QR export** — `docs/specs/008-mobile-qr-export.md`
      `Registry.CreateStatic`, `POST /peers/mobile`, `admin peer
      add-mobile` with QR and `--out`, UI dialog, via-hub netmap entries,
      hub presence from handshakes, forwarding on the hub host, netns
      test with `wg-quick`.
      - The private key exists in `StaticResult` and the response body
        only; the handler zeroes the key array after rendering (the
        config string cannot be zeroed), nothing logs it and the DB
        holds the public key alone (tested by grepping the file).
      - Static peers travel in agent netmaps as `via_hub` entries so
        status shows `via hub` and the filter's visible set includes
        them; clients create no WireGuard peer and no path machine.
      - Presence for phones is the hub handshake (`observeOnce`, under
        3 min); it also updates `last_seen_at`. The server implements
        `Presence` for netmaps and REST, combining sync streams and
        handshakes.
      - Linux sets `/proc/sys/net/ipv4/conf/<iface>/forwarding` after
        the hub is up (per-interface is what the kernel consults for
        ingress traffic); other hosts log that forwarding is theirs to
        enable.
      - Members may add mobile peers for themselves with tags that
        `tagOwners` grants them, mirroring tokens; admins for anyone.
      - QR rendering is server-side: `go-qrcode` for the CLI half-block
        text and an SVG for the embedded UI (no CDN). `gozxing` (tests
        only) decodes the code back to the exact config.
      - Re-adding a deleted name yields a new key; the address is what
        the allocator picks next, usually the freed one.
      - The integration harness uses `public_addr: 0.0.0.0`, so the
        phone test rewrites the exported Endpoint to the server's link
        address before `wg-quick up`.
      - Verified on this box with the real binary (userspace hub,
        agent client on thawr1): `add-mobile` printed the warning, a
        35-row QR and the config; the private key was absent from the
        server log and the SQLite file; `admin peer list` showed
        `alice-phone static offline`; alice-box's `client status`
        listed it `via hub`; `--out` wrote mode 0600 without printing;
        the hub interface's forwarding flag read 1; delete removed it
        from status within 2 s; a member creating for another owner got
        403 over HTTPS and 201 for herself. The wg-quick data path is
        covered by the netns tests, which skip here (no CAP_NET_ADMIN).

## Sprint 3 — distribution and hardening

- [x] **009 Release and install** — `docs/specs/009-release-and-install.md`
      Reproducible release archives with checksums from CI, `thawr
      version` details, server version in the status document,
      `server|client install|uninstall` for systemd, launchd and the
      Windows service manager.
      - Service names are `thawr-server` and `thawr-client` on every
        platform, including the launchd label and plist name (the spec
        draft's dotted labels were dropped for one name everywhere).
      - `internal/svc` writes unit files itself and drives `systemctl`
        and `launchctl` through an injected runner; unit tests run the
        systemd and launchd managers on every OS against a fake runner,
        so no test touches a live init system. Windows uses x/sys
        `windows/svc/mgr` (already a dependency) and is compile-checked.
      - launchd: `Install` only writes the plist because bootstrapping a
        RunAtLoad daemon starts it; `Start` bootstraps (or kickstarts an
        already loaded job), `Stop` boots it out until the next start or
        reboot.
      - The install commands take their process dependencies (service
        manager, root check, executable path, enrolment) from a
        `cliDeps` struct built in `productionDeps`, so tests inject
        fakes without package-level state.
      - `client install` enrols before anything is written outside the
        0600 state directory; the unit never carries `--token` or
        `--server`. `uninstall --purge` fails before touching the
        service when `--yes` is missing.
      - The running binary is refused under a home directory unless
        `--bin` names it: a Homebrew or `/usr/local/bin` install is the
        expectation for a service.
      - Windows: `lifecycleContext` runs `svc.Run` when started by the
        service control manager and cancels the process context on Stop
        or Shutdown; consoles keep Ctrl-C.
      - Release builds: `scripts/release.sh` (bash, CI runner) instead
        of Make macros; `-buildvcs=false -buildid=` plus fixed archive
        mtimes from the commit time make archives byte-identical;
        `make release-verify` proves it on every CI run in about 15 s.
        The Homebrew formula is rendered for a user-maintained tap, not
        published.
      - `server.version` is carried in `NetMap.server_version` (field 7)
        and shown after the server address; the update hint compares
        MAJOR.MINOR through `control.NewerMajorMinor`, and dev builds
        never trigger it.
      - First run on a real Intel Mac (v0.1.0-rc1): the interface now
        defaults to `utun` on macOS for both client and server config,
        since `thawr0` is refused there; `client ping` answers `via hub`
        for phones instead of "unknown peer" (they have no path machine);
        `client status` without sudo needs the `thawr` group
        (`dseditgroup`), documented in the README.
      - Verified on this box with the real binary and a fake `systemctl`
        on PATH (no systemd PID 1 here): `server install --public-addr`
        wrote the config (0640) and unit, ran daemon-reload, enable,
        start; a second install reported "already installed"; a
        non-root run exited 2; `client install` against a live server
        enrolled first and wrote a unit without the token or node
        secret; `uninstall --purge --yes` removed unit and state;
        `make release VERSION=v0.0.0-test` produced five archives whose
        `SHA256SUMS` verified, the extracted Linux binary printed the
        tag and commit, and `make release-verify` passed. The systemd
        integration test skips here and runs on a systemd VM.
- [x] **010 DNS names** — `docs/specs/010-dns-names.md`
      `<name>.thawr` from a resolver in the client fed by the netmap,
      the same resolver on the hub for phones (with forwarding to the
      server host's upstreams), split-DNS registration per platform.
      - Phones are in scope (owner decision): the hub resolver forwards
        everything outside the zone because the WireGuard app sends all
        queries through the tunnel once `DNS =` is set. Upstreams come
        from `dns.upstream` or the host's `/etc/resolv.conf` at start;
        loopback stubs such as 127.0.0.53 are kept, they are the host's
        working resolver.
      - Linux without systemd-resolved manages an `/etc/hosts` block
        (owner decision) instead of warning; the block carries only
        `<name>.thawr`, not the bare name, so a peer never shadows a LAN
        host. Registration and hosts writes happen after the first
        netmap, preceded by an unregister that clears a crashed run.
      - `golang.org/x/net/dns/dnsmessage` is the codec (already in the
        module graph, BSD-3); no third-party DNS library.
      - Names follow visibility: the client resolver knows only its
        netmap, the hub resolver answers a requesting address only with
        peers the policy makes visible to it. Loopback sources are
        always answered so the local host and the tests can ask.
      - `internal/dns.Handle` takes the transport (`tcp bool`) for
        truncation and for forwarding over the arriving transport; the
        spec's signature was amended.
      - `--dns serve` exists for people who configure their resolver
        themselves and for the integration suite, which shares `/etc`
        with the host; every integration client runs with it, and the
        mobile harness strips the phone config's `DNS =` line because
        `wg-quick` would hand it to `resolvconf`.
      - The server test config disables the hub resolver (the fake
        device carries no hub address); `Deps.DNSListen` injects a
        loopback listener where a test needs it, as `DNSOptions.Listen`
        does on the client.
      - Review round (CodeRabbit): the client resolver answers only its
        own host (Allow is the self address plus loopback), so a peer
        the policy lets reach port 53 learns nothing; registration waits
        for a successful bind and is undone on every exit path of `Run`;
        a failed `resolvectl` step reverts; a hosts block with a lost end
        marker is repaired; `Serve` reports a dead listener instead of
        hanging, and the hub stops advertising `dns_listen` then.
      - `TestQRRoundTrip` uses a fixed synthetic key: with the DNS line
        the phone config is a version-12 symbol, and the ZXing port used
        to decode it misreads about one in a hundred random symbols
        (measured 200 runs per EC level), which made CI flaky. The
        encoder is unchanged; whether real scanners share the decoder's
        limit is on the manual phone checklist.
      - Verified here: unit tests for the codec paths, forwarding with a
        fake dialer, every registrar against a temp root and fake
        runner, the daemon serving names over a loopback listener, the
        hub source honouring policy visibility; `make lint`, race tests
        on every package, darwin/arm64 and windows/amd64 builds. The
        netns integration tests compile and skip here (no `ip`); they
        run on the Linux VM. macOS, Windows and a real phone are on the
        manual checklist in TESTING.md.
- [x] **011 Key pinning and audit log** — `docs/specs/011-key-pinning-and-audit-log.md`
      Clients pin the hub key and every peer's `(id, key)` by name and
      hold a changed key out of the tunnel until `thawr client trust`;
      the server keeps an `audit_log` table of every control-plane
      mutation with `thawr admin audit`, a REST endpoint and a UI
      section (threat model T4 and T5).
      - Split (owner decision): 011 is pinning plus audit log; signed
        peer records with an offline admin key are 012. Hold on change
        (owner decision): a held peer gets no WireGuard peer, filter
        rule, name or probe until accepted; nothing is applied "with a
        warning".
      - Pins are keyed by name and carry `(id, key)`. A rename copies
        the pin to the new name and keeps the old one, so a later peer
        taking a known name is held rather than trusted on first
        contact; the plan said "move", copying closes that gap. Pins
        are never pruned by absence for the same reason.
      - The daemon keeps the netmap as received (`offered`) next to the
        filtered one it applied; DNS, filter, paths and status all read
        the filtered map, so holding needed no change in those paths.
        The cache on disk is the received map; held entries are derived
        again from the pins on start. A corrupt `pins.json` is a
        start-up error, never a reset.
      - `rotate-key` prints the `trust` reminder; the rotating device
        cannot vouch for its new key without signing (rule 1), so other
        devices hold it until a person accepts. 012 removes that step
        for admin-signed rotations.
      - Audit rows are appended through the transaction-bound store so
        they commit with the mutation, and a failed append fails the
        mutation (tested by dropping the table under the service). The
        nil `*Auditor` is a no-op so tests and tools without one keep
        working. `PolicyService.Reload` gained the principal.
      - Logins are audited too (ok and failed, the latter as role
        `anonymous`); rate-limited attempts are not, so the limiter
        also bounds audit growth. Failed-login rows are the one place a
        stranger's input (the attempted name) lands in the table.
      - Retention is a daily pruner on the server with an injectable
        interval; the REST `since` filter accepts a duration or an
        RFC 3339 time and uses the server's clock.
      - Windows CI: `TestRelayNeverLogsPayload` read the log buffer as
        soon as the session count dropped, before the close line was
        written; it now waits for the line. A pre-existing race in the
        relay test, not touched by the spec.
      - Verified here: pins rules, daemon hold/trust for a peer and the
        hub against the fake device, CLI trust and status rendering,
        store list/filter/cursor/prune, every audit action with actor
        and target, the endpoint's authorisation and filters, the
        admin command, the server pruner over the admin socket; `make
        lint`, race tests on every package. The netns integration test
        compiles and skips here; it runs on the Linux VM. The UI
        section and the two-device flow are on the manual checklist.
- [x] **012 Network lock** — `docs/specs/012-network-lock.md`
      An Ed25519 lock key on a device the owner controls signs each peer
      record `(id, name, key)`; the server stores and forwards the
      signatures; a client with the lock on holds unsigned peers and
      accepts signed rotations without `trust` (threat model T4, third
      phase-2 item).
      - Owner decisions: the signing key lives on a client device, never
        the server; unsigned peers are held like a changed key, not
        merely flagged; several signers, an existing one adds another
        (`lock key` on the candidate, `lock add-signer` on a signer).
      - The peer name is part of the signed record on purpose:
        `<name>.thawr` is what people type, so a rename must be signed
        again and a swapped name gains an attacker nothing.
      - First contact for the lock record is trusted (pinned as
        offered), the same model as the enrolment and the pins; every
        later record needs a higher generation and a signature by a key
        of the pinned set. A `disabled` record keeps the signer set, so
        only a signer can turn the lock on again; a record without
        signers ends its lineage and the next one starts over.
      - `lock init` sends the record and the first signatures (hub,
        self, every visible peer) in one `SetLock` request, stored in
        one transaction, so no device ever sees the record without its
        signatures and enabling never cuts a working network. The
        server requires the record to exist before it accepts a
        signature, which is why the plan's "signatures first" became
        "both at once".
      - Signatures ride in the netmap per peer, plus the receiver's own
        (`SelfInfo.signatures`, added so a device can tell it is
        unsigned and say so in status and logs).
      - `ListLockPeers` is the one RPC that shows a peer the whole
        registry, gated on the caller being a signer of the current
        record; `lock sign` uses it so peers outside the signer's
        policy view can be signed too.
      - Reading the lock record inside `RotateKey`'s transaction goes
        through the transaction store: the pool has one SQLite
        connection and a read on it deadlocks (found the hard way).
      - Static (ViaHub) peers stay out of scope as in 011: they have no
        WireGuard peer on the client and are reached through the hub,
        whose key is signed.
      - `lock key` restarts the sync stream so the server learns the
        new lock public key at once; reported keys are memory only.
      - Review round (CodeRabbit): the first record, or one restarting
        a lineage, needs a device an admin owns, so a member's device
        cannot hijack the lock; `add-signer` takes the candidate's key
        and refuses when the server reports another, so
        the server cannot promote its own key; `client up
        --lock-signer <key>` pins the signer a fresh device must see in
        its first record, closing the first-contact gap for devices
        enrolled after the lock; old-key signature rows are pruned on
        rotation; duplicate signer peer ids are invalid.
      - Second round: `--lock-signer` requires the first record to be
        signed by that key (listing it is not enough) and the device
        applies nothing until such a record arrives; on an enrolled
        device the flag is persisted while no record is pinned and
        refused otherwise, never ignored; `LockService.Set` reads,
        checks and writes the record in one transaction so competing
        successors cannot both land. Third round: `--lock-signer` and
        `add-signer` take the full public key only; the 8-hex
        fingerprint is 32 bits, enough for a person comparing screens
        and not for authenticating a key.
      - Out of scope, listed in the spec: removing a signer, a quorum,
        rotating a lock key, short-lived keys.
- [x] **013 Exit nodes and subnet routers** —
      `docs/specs/013-exit-nodes-and-subnet-routers.md`
      A Linux peer advertises prefixes or itself as exit node, an admin
      approves, the policy grants (`dst` CIDR outside the overlay,
      `internet`), clients install the routes, the router forwards and
      masquerades; `client exit-node` with fwmark policy routing.
      - Implemented in sprint 4 ahead of the plan (session of
        2026-09-22): the roadmap's sprint 5 stories S5-1 to S5-4 and
        S5-6 are done, S5-5 (routes on macOS and Windows) is done for
        subnet routes only. Open: `tests/routes_test.go` (netns
        integration test, S5-3's second half), the web UI column, and
        the manual checklist on real hosts.
      - Routes ride in the peer's `allowed_ips` next to its /32 rather
        than a separate field; the client derives the OS routes from
        every entry that is not a peer's own /32, so the pre-013 client
        logic needed no change.
      - The policy compiler gets the overlay (`CompileWith`,
        `PolicyService.WithOverlay`): a dst CIDR inside the overlay
        still selects peers, outside it is a route, and one that
        contains the overlay is a validation error. Without an overlay
        (`Compile`) routes are ignored, which keeps every earlier test.
      - A route makes the router visible but opens no port on it:
        `Allowed` is untouched, `Visible` also consults the forward
        rules, `ForwardFor` is separate from `FilterFor`.
      - The router forwards only prefixes from its own state
        (`FilterSetFor` drops netmap forward rules outside them), so a
        server cannot make a peer forward what it never offered
        (threat model T4, requirement 13).
      - Exit-node use and the router role need Linux: the fwmark plus
        `ip rule` scheme (wg-quick's) keeps the endpoint out of the
        tunnel, and forwarding and masquerade are nftables. macOS and
        Windows refuse both with a clear error and still install subnet
        routes. The `wireguard-go` adapter on Linux installs the same
        forward and nat chains next to its userspace input filter.
      - `EnableIPForward` is injectable in `DaemonOptions` so the fake
        device tests run on every platform.
      - `--advertise-routes` omitted keeps the stored set; given, it
        replaces it (an empty list withdraws). A withdrawn prefix
        loses its approval on the server, so re-advertising needs a
        person again.
      - Follow-up (CI on main after the merge): `NetMapBuilder.Build`
        loaded the compiled policy once per question, so two approvals
        in a row could yield a map from two compilations (the gateway
        visible, its exit-node flag missing). `PolicyVisibility` now
        implements `Snapshotter` and a build takes one snapshot; the
        owner rule and test wrappers that embed it need none.
      - Follow-up (rc4 on macOS, 2026-09-23): a manual `client up` next
        to the launchd service took over the socket and raced it for
        UDP 60129, which the userspace adapter rebinds on every netmap
        (wireguard-go reopens its socket for each `listen_port` line,
        the same number included). Three fixes: `NewDaemon` refuses to
        start while the socket answers (`ErrAlreadyRunning`, exit 2), a
        stored listen port that is taken at start is replaced and
        persisted, and the userspace adapter sends `listen_port` only
        when it changes. The kernel already ignores an unchanged port.

## Fixes after v0.1.0-rc5 (review of 2026-09-29)

Found while using rc5 on macOS with a phone and in a review of the
tree that followed. One commit each, highest severity first.

- [x] Policy names stay with their peer. `peer:<name>` grants follow
      the name, so a rename dropped them and the next device taking the
      name inherited them.
      - Rename refuses a policy-selected name without `--force`; the
        error names the rules. The new name is not checked: renaming
        into a selected name is how an admin grants it on purpose.
      - Only a token an admin issued for the name may take it at
        enrolment, checked against the policy in force then (a member's
        token from before a reload that selects the name gets a numbered
        name). Migration 0006 adds `issued_by_admin`, since `created_by`
        attributes socket-issued tokens to their owner; older tokens
        count as not admin-issued. Members also cannot issue such a
        token or add a static peer with the name. A rename to the same
        name is a no-op.
      - Delete is not guarded: the freed name stays protected by the
        enrolment rule.
      - Enrolment reads the policy's peer names inside its transaction,
        which holds the store's only connection. `PolicyService.Compiled`
        therefore no longer holds its mutex while it reads the registry;
        before, the two deadlocked (caught by macOS CI).
- [x] The exit-node choice is kept by peer id (`exit_node_id` in
      state.json), with `exit_node` as the last known name for status.
      State written by rc5 names the peer only; the first netmap with
      an exit node of that name fills in the id.
- [x] The client adopts `SelfName` from every netmap (it was parsed and
      never used) and persists it. Reads of the name moved under
      `d.mu`, since it is no longer fixed after enrolment. The logger's
      `peer` attribute keeps the name the daemon started with until
      the next start; the "renamed by the server" line links the two.
- [x] A permission error on the client socket is no longer read as
      "nobody there". `socketBusy` returns it; status, down and up exit
      2 with "no permission to use the client socket …; run it with
      sudo" (Administrator prompt on Windows), and `main` adds the same
      hint to any other permission error. The socket test is skipped as
      root, which bypasses file permissions.
- [x] `client start|stop` wrap `svc.Manager.Start/Stop` (launchd
      bootstrap or kickstart, systemctl, the Windows SCM). `start`
      refuses while a foreground `client up` holds the socket, since the
      service would exit at once with "already running". The service
      restart policies (`SuccessfulExit=false`, `Restart=on-failure`)
      stay: a clean `down` staying down is what `down` promises.
- [x] `client install` checks for an installed service before
      enrolment and `--advertise-*`; installed, it refuses any flag that
      writes state or is baked into the service (`--dns`, `--interface`,
      `--log-level`, `--bin`) and otherwise starts the service if
      stopped, unless a foreground client holds the socket. Not
      installed, it runs the same `CheckNotRunning` as `up` first.
      Both that and `client start` check the socket the service was
      installed with, read back from the unit, plist or SCM entry
      (`svc.Manager.Args`), not one given on the command line. A socket
      the check may not open stops the start instead of counting as free.
- [x] The admin socket error tells "no socket here" (run on the server
      host) from "permission denied" (sudo). Left as is: the `thawr`
      group on admin.sock grants nothing while the socket sits in the
      0700 data_dir; moving it is a layout change for a spec.
- [x] DNS: `hub` is refused as a peer name everywhere a name is set and
      counts as taken at enrolment; an existing peer called `hub` is
      left alone. Negative answers in the zone carry an SOA with TTL and
      MINIMUM 30 s (reverse-zone negatives are unchanged); an SOA query
      at the apex answers it. The no-upstream
      state is decided once at start, like the upstream list itself.
      README: the server host resolves no `.thawr` names, `dig` bypasses
      the macOS resolver file, phones from before the resolver need the
      DNS line added in the app.
- [x] Windows service stop: the process reports Stopped before it exits
      (`lifecycleContext` returns `func(error)`; the handler returns
      once the work ended, with service exit code 1 on failure). Install
      sets `SetRecoveryActionsOnNonCrashFailures`, so a failed run still
      restarts. Found by reading the code; the handler is tested on the
      windows-latest runner, not yet on a real installed service.
- [x] Windows service output goes to `%ProgramData%\Thawr\logs\<service>.log`:
      `main` points stdout, stderr and the standard handles (for panics)
      at it when running as a service; not rotated, like the launchd log.
      `svc.LogPath` is shared by the redirect and `Logs`. The file is
      opened through `fsperm.OpenLog`, which secures `%ProgramData%\Thawr`
      and `logs` first and refuses a link or a file with a second name
      (checked on the open handle): as SYSTEM the service must not
      append through a link a standard user planted. The owner and
      access-list code moved from `internal/client` to `internal/fsperm`
      for that; socket files are secured through a handle opened with
      `FILE_FLAG_OPEN_REPARSE_POINT`, and a socket that cannot be
      secured is no longer served (it was a warning).
- [x] Windows client socket and state directory (changes the "same
      socket path on every platform" line in ARCHITECTURE.md, agreed
      with the owner): `DefaultSocket()` is `%ProgramData%\Thawr\client.sock`
      on Windows. `restrictToAdmins` sets a protected access list
      (SYSTEM, Administrators, owner rights) on the state directory at
      every secret write, which fixes existing installs on the first
      save, and on the socket file. The owner entry keeps non-elevated
      test runs working and adds nobody, since owners may rewrite the
      list anyway. Before the access list, Administrators become the
      owner (with the take-ownership privilege where the current owner
      shut them out), since a standard user who created
      `%ProgramData%\Thawr` before the first install would otherwise
      keep owner rights; a non-elevated run accepts only SYSTEM,
      Administrators or itself as owner. A link or junction is refused,
      and a secret's temporary file is always a new,
      uniquely named one (`os.CreateTemp`), so a planted `*.tmp` cannot
      pass its access list on through the rename and concurrent writers
      of one file never share it. An access list already in place is
      left alone, so only the first save walks the directory.
- [x] Windows server: `data_dir` (holding `server.key`, the TLS key and
      the database) and the admin socket (full admin without a login)
      kept the inherited access list of `C:\`, which lets every local
      user create and read. `secureDataDir` runs `fsperm.RestrictToAdmins`
      on every start, also on a new directory, and `secureSocket` on the
      admin socket; `writeSecretFile` uses a fresh `os.CreateTemp` file.
      The default path stays `C:\var\lib\thawr`: moving it would leave
      an existing server's keys and database behind.

## Sprint 6 — operations

- [x] **014 Operations** — `docs/specs/014-operations.md`
      Backup and restore, Prometheus metrics, ACME with the pinned
      certificate kept for clients. Three PRs: backup and restore,
      metrics, ACME.
      - Owner decisions (2026-10-02): the archive is plain `tar.gz`
        written 0600, not encrypted (no new dependency; Thawr implements
        no cryptography, operators encrypt with their backup tool);
        metrics on the admin socket plus an opt-in listener; ACME picks
        the certificate by SNI so client pins survive renewals.
      - Backup and restore done. The archive is a `tar.gz` with
        `manifest.json` first (size and SHA-256 per file); `Extract`
        verifies while it writes and refuses links, unsafe paths and
        anything the manifest does not list exactly.
      - `GET /api/v1/backup` is registered only on the admin socket's
        handler (`RESTDeps.Local`), not by role: an admin session over
        HTTPS gets 404, because the archive holds `server.key`.
      - The server builds the archive in a temporary directory inside
        `data_dir` before streaming it, so errors become a 500 instead
        of a cut stream, the response has a Content-Length and a SHA-256
        header, and the CLI writes nothing it could not verify.
      - The snapshot is `VACUUM INTO` on the store's single connection
        (ADR 0002), not modernc's backup API: no driver-specific code,
        and the copy is compacted.
      - Restore extracts into the system temp dir first because the
        target `data_dir` is not known until the config is (on a fresh
        host it comes from the archive). A restore that fails after
        writing empties `data_dir` again (it was empty or moved aside),
        so a retry needs no `--force`.
      - The client's instance lock moved to `internal/flock`; the
        server takes `data_dir/thawr.lock` with it, and restore takes
        the same lock, so a restore and a server exclude each other
        even when the admin socket is gone. `--force` renames data_dir
        while still holding that lock (Unix keeps a lock across a
        rename; on Windows the rename is retried once after releasing
        it and fails if a server took it), rather than a lock file next
        to data_dir: under the systemd unit the server may write only
        inside data_dir.
      - Metrics done. The text format is written by hand
        (`internal/metrics`, ~100 lines) instead of pulling in the
        Prometheus client and its dependencies; each scrape is built from
        counters the server already has, so nothing registers globally.
      - `/metrics` on the admin socket is registered like the backup
        route (`RESTDeps.Local`); the optional TCP listener has its own
        mux with `/metrics` only, so it can never expose the API.
      - `thawr_peers_online` adds static peers with a fresh hub handshake
        to the hub's agent count, the same rule `Server.Online` uses.
      - ACME done. Only the configured domain goes to autocert; every
        other server name (the clients' `thawr-pinned.invalid`, none,
        or another name) gets the pinned certificate, which is narrower
        than the spec's first draft ("any other name: ACME") and keeps
        old clients that dial an alias working.
      - The server asks for the ACME certificate once at start, in the
        background: Go's HTTP server ends a TLS handshake after its
        10 s header timeout, which a first issuance can exceed, and a
        wrong domain or port shows in the log at once.
      - Warnings (`Config.Warnings`, logged by `server` and `--check`)
        for acme mode with `min_client_version` below 0.2 and for
        `listen.https` off port 443, where TLS-ALPN-01 cannot reach it.
      - Verified against Pebble with real TLS-ALPN-01 validation (DNS
        from `pebble-challtestsrv`): issued, served to the domain only,
        renewal changes the browser certificate and not the pinned one.
        Pebble v2.10.1 answers the finalize request without the
        `Location` header that x/crypto's `CreateOrderCert` reads, so
        issuance fails there; v2.4.0 sends it and works. Let's Encrypt
        itself is the manual staging step 8, kept instead of a
        build-tagged test that CI would never run.

## Sprint 7 — IPv6 overlay

- [x] **015 IPv6 overlay** — `docs/specs/015-ipv6-overlay.md`
      Every peer gets an IPv6 address next to its IPv4 one. Three PRs:
      control plane, data plane (`internal/wg` and the hub), client with
      names, status and integration tests.
      - Owner decisions (2026-10-03): the IPv6 address is derived, not
        allocated (the IPv4 address in the last 32 bits of the ULA /64);
        exit nodes carry `::/0` with NAT66, so native IPv6 no longer
        leaks around them; a capability flag (`ipv6` in Enroll and Sync)
        rather than a forced upgrade, so clients from before 015 keep
        an unchanged IPv4 netmap.
      - The prefix is chosen once and kept in meta `overlay_ipv6`, like
        the server key fingerprint: a configured prefix is recorded, an
        empty one generated (RFC 4193), and a changed one refuses to
        start, since every peer's address would move. Restore checks the
        same before writing.
      - `ipv6_capable` is per peer and set from every Sync; a change bumps
        the generation, because other capable peers' maps gain or lose
        that peer's address. A capable receiver sees another peer's IPv6
        only when that peer is capable too: an address no device
        configured would blackhole traffic.
      - Filter and forward rules carry one source of either family
        (`Src`, was `SrcIPv4`); the policy emits a second rule per
        source with an IPv6 address, and `internet` adds `::/0` for it.
        An IPv6 CIDR selector selects peers (whole peers, both
        families); IPv6 subnet routes stay out of scope, so Validate
        rejects IPv6 prefixes outside the IPv6 overlay.
      - Selectors try addresses before `kind:name`, since an IPv6 address
        has colons; a dst may bracket it (`[fd..::7]:22`).
      - Control plane done (PR 1). Phones created from now on get both
        addresses in their config; until the hub has IPv6 (PR 2) that
        traffic has nowhere to go, which no release ships.
      - Linux has no per-interface IPv6 forwarding switch, and turning on
        `net.ipv6.conf.all.forwarding` makes the kernel ignore router
        advertisements where `accept_ra=1`. Every interface (and
        `default`) with 1 moves to 2 first; both come back on stop, and
        nothing is touched when forwarding was already on.
      - IPv6 addresses go on without DAD (`IFA_F_NODAD`): the derived
        address is unique by construction. A kernel booted without IPv6
        keeps IPv4 only (`wg.IPv6Available`), and that client says
        `ipv6: false`, so no peer is handed an address it cannot reach.
      - ICMPv6 errors (1–4) and neighbour discovery (133–137) pass both
        filters without a rule; echo (128) follows the visible set like
        ICMP echo. The userspace filter walks at most 8 extension
        headers; a later fragment is treated like an IPv4 one.
      - NAT66 needs `MasqueradeFrom6`: without the overlay's `/64` no
        IPv6 masquerade rule exists, so a router never rewrites the
        host's own IPv6 traffic. An exit node without the IPv6 overlay
        forwards IPv4 only.
      - The resolvers keep their IPv4 listener and answer AAAA there
        (the spec's "queries from the own IPv6 address" became moot);
        the hub resolver tells IPv6 addresses only to capable
        requesters. The client answers `ip6.arpa` for all of `fd00::/8`,
        since its `/64` may arrive after the resolver starts.
      - `client status` shows the IPV6 column only when a row has an
        address, so IPv4-only networks see the table they know.
      - Not run here: this container's kernel has IPv6 disabled and no
        iproute2, so the netns IPv6 tests (`TestIPv6OverlayEndToEnd`,
        `TestIPv6PhoneViaHub`) and the TESTING 015 checklist are the
        owner's to run; there is no netns exit-node IPv6 test.

## Phase 2 candidates (scheduled as specs 014–021 in `docs/roadmap/`)

- OIDC identity provider plugin (ADR 0006).
- IPv6 overlay.
- Separate relay nodes (`thawr relay`).
- ACME TLS mode, Prometheus metrics, `thawr admin backup` (spec 014,
  sprint 6).
- Workload / agent identity: short-lived tokens issued by CI or an
  orchestrator, using the existing `kind: agent`.
- Short-lived peer keys with automatic rotation and expiry, and binding
  an agent identity to the process rather than the host (VISION,
  "identity layer for agents").

## Decisions reviewed by the owner (2026-09-02: all accepted as written)

- D1 License: Apache-2.0 confirmed; Phase 1 replaced the initial MIT
  `LICENSE` with the canonical Apache-2.0 text.
- D2 STUN: copy `tailscale.com/net/stun` into `internal/stun`
  (BSD-3, ~400 lines, no transitive deps) rather than importing the
  `tailscale.com` module (large dependency tree). Alternative:
  `github.com/pion/stun` (MIT).
- D3 CLI framework: `github.com/spf13/cobra` for nested subcommands and
  help. Alternative: stdlib `flag` with a hand-written dispatcher.
- D4 Enforcement of port-level policy on the receiver (nftables with
  kernel WireGuard, userspace filter with `wireguard-go`) instead of a
  userspace packet multiplexer in front of WireGuard. Cheaper to build,
  keeps the WireGuard device as the only packet sender.
- D5 Mobile peers are routed through the server's WireGuard hub, which
  means the server sees their plaintext (threat model T4). The
  alternative (no phones in v1) contradicts the brief.
- D6 Relay transport is TLS over the HTTPS port with an HTTP Upgrade,
  not a separate port, so users open exactly one TCP and two/three UDP
  ports.
- D7 Control-channel client auth is a bearer node secret over pinned
  TLS, not mTLS or a second signing key; simpler, and the WireGuard key
  stays the only long-lived identity on the device.
