# Spec 009 — Release and install

Sprint 3. Depends on: 001 (server bootstrap, `--check`), 003 (client
daemon, `client up`), 007 (status document). Packages: `cmd/thawr`
(`version`, `server install|uninstall`, `client install|uninstall`),
new `internal/svc` (service manager adapters), `.github/workflows`
(release pipeline), `Makefile` (`release`).

## Goal

Someone who is not the developer can put Thawr on a VPS and on their
laptops in ten minutes: download a release binary, verify its checksum,
run one `install` command per machine, and have the server and the
clients start at boot and restart on failure. Releases are built by CI
from a tag, reproducibly, with published checksums (threat model T6).

## User story

As the owner of a homelab, I download `thawr` for my VPS, run
`thawr server install --public-addr vpn.example.com`, create a token,
and on my Mac run `sudo thawr client install --server ... --token ...
--fingerprint ...`. Both machines survive a reboot without me touching
them again. When a new release is out, I replace the binary and restart
the service; nothing else changes.

## Commands

```
thawr version [--json]
thawr server install [--config /etc/thawr/server.yaml] [--public-addr host[:port]] [--bin path] [--no-start]
thawr server uninstall [--purge]
thawr client install --server URL --token TOKEN --fingerprint sha256:... [--name NAME] [--interface IFACE] [--bin path] [--no-start]
thawr client install                       # already enrolled: only the service
thawr client uninstall [--purge]
make release VERSION=v0.1.0                # dist/ with archives, SHA256SUMS, Homebrew formula
```

`version` prints one line, `thawr v0.1.0 (go1.26.8, linux/amd64,
commit 5f795a3, built 2026-09-05)`; `--json` returns `{version,
go, os, arch, commit, built_at}`. Development builds print `dev`
with the VCS revision from Go's build info when present.

## Behaviour

### Version

- `main.version` stays the single source; `make build` sets it from
  `git describe --tags`, release builds from the tag. When it is `dev`
  or empty, `version` falls back to `debug.ReadBuildInfo` (`vcs.revision`
  shortened to 7 hex characters, `vcs.time`, `vcs.modified` shown as
  `-dirty`).
- Release versions are `vMAJOR.MINOR.PATCH`; `min_client_version` keeps
  its `MAJOR.MINOR` form and `checkVersion` accepts both with and
  without the `v` prefix (already true; a test pins it).
- The netmap carries `server_version` (proto `NetMap.server_version`);
  the client stores it and the status document gains
  `server.version`. `client status` shows it in the header line and,
  when the server's `MAJOR.MINOR` is ahead of the client's, appends
  `(client update available)`. Nothing ever contacts a third party for
  this: the only version source is the user's own server.

### Release pipeline

- `make release VERSION=vX.Y.Z` builds `dist/thawr_vX.Y.Z_<goos>_<goarch>`
  for linux/amd64, linux/arm64, darwin/arm64, darwin/amd64,
  windows/amd64 with `CGO_ENABLED=0 -trimpath -buildvcs=false
  -ldflags "-s -w -buildid= -X main.version=vX.Y.Z"` and `-mod=readonly`,
  packs Unix targets as `.tar.gz` and Windows as `.zip` (binary,
  `LICENSE`, `NOTICE`, `README.md`, `config/server.example.yaml`),
  writes `dist/SHA256SUMS`, and renders `dist/thawr.rb` (Homebrew
  formula for a tap) from `packaging/homebrew/thawr.rb.tmpl` with the
  darwin checksums. Archive timestamps are fixed to the tag's commit
  time so the archives themselves are reproducible.
- `make release-verify` builds every target twice into separate
  directories and fails when any binary differs; CI runs it on every
  release and on pull requests that touch `Makefile` or the workflow.
- `.github/workflows/release.yml` runs on tags `v*`, or by hand
  (`workflow_dispatch` with a `version` input, refused when that tag
  already exists; the release then creates the tag on the commit it
  built): lint and tests as
  in `ci.yml` plus `govulncheck` (a known reachable vulnerability stops
  the release), then `make release release-verify`, then creates the
  GitHub Release with `gh release create` (the runner's `gh`, no
  third-party action) and uploads `dist/*` including `SHA256SUMS`; when
  the release for the tag already exists (published by hand, which
  also creates the tag) the archives are uploaded to it instead.
  Pre-release tags (`v0.1.0-rc1`) are marked pre-release. The workflow
  has `contents: write` only in the publish job.
- README gains an "Install" section: download, `sha256sum -c`, put the
  binary in `/usr/local/bin`, then the install commands below. The
  Homebrew formula is attached to the release for a user-maintained
  tap; publishing a tap is not part of the repo.

### Service install (`internal/svc`)

One small interface, one implementation per platform, and an injected
command runner so unit tests never call `systemctl` or `launchctl`:

```go
type Manager interface {
    Install(ctx context.Context, s Service) error   // write unit, register, enable
    Start(ctx context.Context, name string) error
    Stop(ctx context.Context, name string) error
    Uninstall(ctx context.Context, name string) error
    Status(ctx context.Context, name string) (State, error) // running | stopped | absent
}
type Service struct {
    Name        string   // thawr-server | thawr-client
    Description string
    Exec        string   // absolute path of the binary
    Args        []string // e.g. server --config /etc/thawr/server.yaml
    Env         map[string]string
    Restart     bool
}
```

- Linux (`svc_linux.go`): unit files at
  `/etc/systemd/system/<name>.service` (mode 0644), then
  `systemctl daemon-reload`, `systemctl enable --now <name>` (or
  `enable` alone with `--no-start`). The unit runs as root (the hub and
  the client interface need `CAP_NET_ADMIN`) with `Restart=on-failure`,
  `RestartSec=2`, `NoNewPrivileges=yes`, `ProtectSystem=strict`,
  `ProtectHome=yes`, `ReadWritePaths=` for the data or state directory
  and `/var/run/thawr`, `LimitNOFILE=65536`. Output goes to the
  journal. The server unit adds `ExecReload=/bin/kill -HUP $MAINPID`
  (policy reload from 006).
- macOS (`svc_darwin.go`): plists at
  `/Library/LaunchDaemons/thawr-<server|client>.plist` (mode 0644, label
  `thawr-server` / `thawr-client`), `RunAtLoad`, `KeepAlive` with
  `SuccessfulExit=false`, stdout and stderr to
  `/Library/Logs/Thawr/<name>.log`; `launchctl bootstrap system` and
  `bootout` do the registration; `launchctl kickstart -k` restarts.
- Windows (`svc_windows.go`): `golang.org/x/sys/windows/svc/mgr`
  creates the service (`SERVICE_AUTO_START`, recovery: restart after
  2 s) with the arguments above; `thawr server` and `thawr client up`
  detect `svc.IsWindowsService()` and run under `svc.Run` with stop and
  shutdown mapped to the context cancellation they already use.
  Compile-checked in CI; manual checklist as for the adapters.
- Everything else (`svc_other.go`): `ErrUnsupported` with a message
  naming the platform.
- `Exec` defaults to `os.Executable()` resolved through symlinks;
  `--bin` overrides it. Install refuses a relative path, a path that is
  not executable, or one under a user's home unless `--bin` is
  explicit (a Homebrew or system location is expected).
- Install requires root (Unix: euid 0; Windows: elevated). Otherwise
  exit 2 with `run as root (sudo)`.
- Unit files and plists never contain secrets. `client install` with
  `--token` enrols first (`client.Enroll`, exactly as `client up`
  does), and only then writes the unit that runs `thawr client up`
  with the state directory and socket flags. The token is consumed
  before anything touches disk outside the 0600 state directory.
- `server install --public-addr` writes the minimal config
  `public_addr: <value>` to `--config` (mode 0640, directory 0750)
  when the file does not exist, and refuses to overwrite one that
  does. It then runs the equivalent of `thawr server --check` and
  aborts on failure before installing anything.
- `uninstall` stops and removes the service. `--purge` additionally
  deletes the server `data_dir` (after printing what it will delete
  and requiring `--yes`) or the client state (via `client.Forget` plus
  the netmap cache). Without `--purge` all data stays, so a reinstall
  after an upgrade reuses the enrollment.
- Every install and uninstall prints what it wrote and the commands
  to inspect the service (`journalctl -u thawr-client -f`,
  `tail -f /Library/Logs/Thawr/thawr-client.log`, `sc query
  thawr-client`).

### Upgrade

Replace the binary in place and restart the service (`systemctl
restart thawr-server`, `launchctl kickstart -k system/thawr-server`).
The server applies pending migrations at start (001); the client
re-enrols nothing. A client older than `min_client_version` is refused
at sync with the existing `ErrVersion`, which `client status` already
surfaces as `reconnecting`; the new `(client update available)` hint
gives the user the earlier warning. Documented in README under
"Upgrading".

## Acceptance criteria

- [ ] `thawr version` and `--json` print the fields above; a `dev`
      build shows the VCS revision; a release build shows the tag.
- [ ] `make release VERSION=v0.0.0-test` on a clean checkout produces
      five archives plus `SHA256SUMS` and `thawr.rb`, and
      `make release-verify` finds byte-identical binaries across two
      builds (test builds two targets to keep it fast in CI).
- [ ] `release.yml` on a `v*` tag publishes a GitHub Release with every
      archive and `SHA256SUMS`; the checksums match the archives.
- [ ] On Linux with systemd (integration, needs root):
      `thawr server install --public-addr 127.0.0.1:8443` writes the
      config and unit, the service is `active`, `thawr admin` works
      over the socket, `uninstall` leaves `data_dir` in place and
      `uninstall --purge --yes` removes it.
- [ ] `thawr client install --server ... --token ... --fingerprint ...`
      enrols, writes a unit containing no token, starts the service,
      and `client status` exits 0 after it; `client install` a second
      time without a token reports "already installed" and exits 0.
- [ ] Unit files, plists and the Windows service command line contain
      no token, node secret or key (`TestServiceFilesNoSecrets`).
- [ ] `install` without root exits 2; `install` on an unsupported
      platform exits 2 with a message.
- [ ] `client status` shows `server v0.2.0 (client update available)`
      when the server reports a newer `MAJOR.MINOR`; the status
      document validates against `docs/status.schema.json` with the
      new `server.version` field.
- [ ] macOS: `sudo thawr client install ...` starts a launchd daemon
      that survives a reboot (manual checklist, recorded in TESTING.md).

## Test cases

- `TestVersionString`, `TestVersionJSON`, `TestVersionFallbackBuildInfo`
  (`cmd/thawr`).
- `TestCheckVersionPrefixes` (`internal/control`).
- `TestSystemdUnitRender`, `TestLaunchdPlistRender` (golden files),
  `TestServiceFilesNoSecrets`, `TestInstallRequiresRoot`,
  `TestInstallRefusesRelativeBin` (`internal/svc`, `cmd/thawr`, using
  a fake `Manager` and a fake process runner for `systemctl` and
  `launchctl`).
- `TestClientInstallEnrolsBeforeWritingUnit` (fake manager records the
  order: enrolment RPC, then `Install`).
- `TestServerInstallWritesMinimalConfig`, `TestServerInstallRefusesExistingConfig`.
- `TestStatusServerVersionHint` (`cmd/thawr`).
- `TestReleaseReproducible` (`make release-verify`, CI job).
- Integration: `TestServerInstallSystemd`, `TestClientInstallSystemd`
  (skip when `systemctl` is absent or PID 1 is not systemd).

## Out of scope

- Publishing to a Homebrew tap, apt or rpm repositories, Chocolatey,
  container images (the formula and the archives are the inputs for
  them).
- Self-update (`thawr update`): the binary never downloads anything.
- Running the services as a dedicated unprivileged user (needs
  capability handling per platform; phase 2).
- Code signing and notarisation for macOS and Windows.
- Creating the `thawr` group for socket access (documented as a manual
  step).
