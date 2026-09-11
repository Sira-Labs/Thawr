# Thawr — Backlog

Status legend: `[ ]` open, `[~]` in progress, `[x]` done. One spec per
session; mark it here and add one line per non-obvious decision below the
entry.

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
        or fingerprint and refuses when the server reports another, so
        the server cannot promote its own key; `client up
        --lock-signer <fp>` pins the signer a fresh device must see in
        its first record, closing the first-contact gap for devices
        enrolled after the lock; old-key signature rows are pruned on
        rotation; duplicate signer peer ids are invalid.
      - Out of scope, listed in the spec: removing a signer, a quorum,
        rotating a lock key, short-lived keys.
- [ ] **013 Exit nodes and subnet routers** — advertised prefixes gated
      by policy (spec to be written).

## Phase 2 candidates (not scheduled)

- OIDC identity provider plugin (ADR 0006).
- IPv6 overlay.
- Separate relay nodes (`thawr relay`).
- ACME TLS mode, Prometheus metrics, `thawr admin backup`.
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
