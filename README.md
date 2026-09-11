<div align="center">

![Thawr](docs/assets/logo-dark.svg#gh-dark-mode-only)
![Thawr](docs/assets/logo-light.svg#gh-light-mode-only)

</div>

# Thawr

**One binary. No cloud. Works offline.**

[![CI](https://github.com/thedatadudech/Thawr/actions/workflows/ci.yml/badge.svg)](https://github.com/thedatadudech/Thawr/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/thedatadudech/Thawr?include_prereleases&label=release)](https://github.com/thedatadudech/Thawr/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/thedatadudech/Thawr)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Thawr is a self-hosted, WireGuard-based private network (mesh VPN / ZTNA)
that connects laptops, servers, phones and home machines across the
internet as if they were on one LAN. The name comes from the cave near
Mecca where the Prophet Muhammad ﷺ and Abu Bakr found shelter during the
Hijra: hidden, protected, reachable only by those who belong.

Status: release candidate. `v0.1.0-rc3` runs a hub on a VPS with a
Mac and a phone as peers; specs 001–009 (enrollment, key distribution,
NAT traversal, relay, ACL policy, status, mobile QR, release and install)
are implemented and covered by unit and netns integration tests. Config
keys and the admin API may still change before `v0.1.0`. The design
lives in `docs/`; the implementation follows one spec at a time from
`docs/specs/` and is tracked in `TASKS.md`.

## What you get

- A single `thawr` binary that runs as the control server, as the client
  on every device, and as the admin CLI.
- WireGuard for the data plane, kernel module where available,
  `wireguard-go` otherwise. Thawr never implements cryptography.
- Direct peer-to-peer connections through NAT, with a relay built into
  the server as fallback. Traffic between peers is end-to-end encrypted;
  the relay forwards opaque packets.
- SQLite embedded; the whole server state is one directory.
- Local users and one-time enrollment tokens. No identity provider
  required. OIDC optional.
- A YAML policy file you keep in git. Default deny: peers without a
  rule cannot see each other, and the receiving peer filters ports
  (nftables with kernel WireGuard, a userspace filter otherwise).
  `thawr admin policy check`, `reload` and `show` manage it live.
- Phones use the official WireGuard app via a QR code.
- Every device pins the hub's key and the key of every peer it reaches
  directly: a key that changes is held out of the tunnel until you run
  `thawr client trust <name>`, so a compromised server cannot silently
  swap a key. Phones are reached through the hub, whose key is pinned.
  The server keeps an audit log of every change (`thawr admin audit`).
- The network lock goes further: `thawr client lock init` on a device
  you control creates a signing key the server never sees, and from
  then on every device applies only peers a signer vouched for with
  `thawr client lock sign <name>`. A server that inserts a device or
  swaps a key can only make it show up as `unsigned`. That holds once
  a device has pinned the lock record; a device enrolled afterwards
  pins the first record it sees, so give it the signer's fingerprint
  at enrolment (`thawr client up --lock-signer <lock public key>`)
  when the server itself may be hostile.
- Nothing phones home. It starts and runs with no internet access.

## Install

Releases are built by CI from a tag, reproducibly, and ship with
checksums. Download the archive for your platform from the GitHub
Releases page, verify it, and put the binary on the path:

```
curl -LO https://github.com/thedatadudech/Thawr/releases/download/v0.1.0/thawr_v0.1.0_linux_amd64.tar.gz
curl -LO https://github.com/thedatadudech/Thawr/releases/download/v0.1.0/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar xzf thawr_v0.1.0_linux_amd64.tar.gz
sudo install -m 0755 thawr_v0.1.0_linux_amd64/thawr /usr/local/bin/thawr
thawr version
```

macOS: the `darwin_arm64` (Apple silicon) or `darwin_amd64` archive,
`shasum -a 256 -c`. Windows: the `.zip`, `Get-FileHash`. Each release
also carries `thawr.rb`, a Homebrew formula for your own tap. The
`thawr` binary is the same on every machine; what differs is the
subcommand you install.

## Quick start

Server, on a host with a public address (Linux with systemd, or macOS):

```
sudo thawr server install --public-addr vpn.example.com
thawr admin user create markus --role admin
thawr admin token create --owner markus --kind human
```

`server install` writes `/etc/thawr/server.yaml` with that one line,
validates it, and registers `thawr-server` to start at boot
(`journalctl -u thawr-server -f` follows the log). Without a service
manager, `thawr server --config /etc/thawr/server.yaml` runs it in the
foreground.

Client, on any machine:

```
sudo thawr client install --server https://vpn.example.com --token thawr_... --fingerprint sha256:...
thawr client status
thawr client ping <peer>
```

`client install` enrols the device with the one-time token, then
registers `thawr-client` (systemd, launchd or a Windows service) to run
`thawr client up` at boot; the token never reaches the service file.
Run it on every machine except the server: the server host is already
a peer (the hub), and `client install` refuses to run there.
`sudo thawr client up --server ... --token ...` does the same in the
foreground. `client up` enrols the device on first run and then keeps
the WireGuard interface in sync with the server until stopped. The
client's socket is readable by root and the `thawr` group; create the
group and add yourself (`groupadd thawr && usermod -aG thawr $USER`;
macOS: `dseditgroup -o create thawr && dseditgroup -o edit -a $USER -t
user thawr`) to run `client status` without sudo. `client status` shows
in one table whether the control connection, the path to a peer or the
policy is the problem (`--json` for scripts, validated by
`docs/status.schema.json`; exit codes 0 connected, 1 server unreachable,
2 usage, 3 not running):

```
thawr 0.1.0 · alice-laptop 100.64.0.7 · server vpn.example.com:8443 connected (netmap #42, 3s ago)
WireGuard: kernel · thawr0 · listen 41820 · NAT: cone (reflexive 203.0.113.9:41820)

PEER          IP            KIND     OWNER   PATH                           HANDSHAKE   RX / TX
homelab-nas   100.64.0.3    server   -       direct 198.51.100.4:51820      12s         1.2 MB / 340 kB
build-box     100.64.0.9    agent    -       relay                          3m          0 B / 0 B
hub           100.64.0.1    server   -       direct vpn.example.com:51820   25s         4 kB / 4.2 kB

Filter: 3 rules · 0 dropped (last 5 min)
```

Every peer has a name: `ssh nas.thawr`, `curl http://build-box.thawr:8000`,
`ping alice-laptop.thawr`. The client serves the `thawr` zone on its
own overlay address from the netmap it already has, so names work
exactly when the tunnel works and nothing outside the network is asked.
It tells the OS to send `.thawr` queries there (systemd-resolved, a
managed block in `/etc/hosts` where resolved is absent, a resolver file
on macOS, an NRPT rule on Windows) and undoes that on `client down`.
`--dns serve` keeps the resolver without touching the system
configuration, `--dns off` disables it; `client status` shows which.

Phones join with the official WireGuard app: `thawr admin peer add-mobile
--owner markus --name markus-phone` prints a QR code to scan (once; the
server keeps only the public key). The config points the phone at the
hub's resolver, so names work there too; because the app then sends
every DNS query through the tunnel, the server forwards anything
outside `.thawr` to its own resolvers (`dns.upstream`, or the host's
`/etc/resolv.conf`). A phone learns only the names of peers the policy
lets it reach. Phone traffic goes through the
server's hub, so the server can read it, unlike the end-to-end tunnels
between laptops and servers; see the threat model.

Peers find each other through STUN and WireGuard hole punching:
same-LAN addresses first, then the public address behind the router;
`client ping` forces the probe and shows the path in use along with the
echo replies. `thawr admin peer list` and `admin peer show <name>` give
the admin the same view across the whole network, including each
peer's candidates and compiled filter. When no direct path exists (two symmetric NATs, a strict
firewall) the packets go through the relay built into the server, still
end-to-end encrypted, and the path upgrades to `direct` on its own when
the network allows it.

Ports on the server: TCP 443 (control, UI, relay), UDP 3478–3479
(STUN), UDP 51820 (WireGuard hub for phones), UDP and TCP 53 on the hub
address only (`100.64.0.1`, reachable through WireGuard, never from the
internet). When 443 is taken (a
reverse proxy, Docker, CapRover) set `listen: {https: ":8443"}` and
`public_addr: vpn.example.com:8443` in `server.yaml`; the server
opens the host's forward chain for the hub interface itself, also on
Docker hosts whose default `FORWARD` policy is `DROP`.

## How it compares

| | Tailscale | NetBird | Headscale | Thawr |
|---|---|---|---|---|
| Control plane | Vendor cloud | Vendor cloud or self-host (multi-service) | Self-host, re-implements Tailscale's protocol | Self-host, own protocol, one process |
| Identity | External IdP required | External IdP required | Tailscale clients + OIDC or pre-auth keys | Local users + tokens; OIDC optional |
| Relay | Vendor DERP fleet | Vendor TURN or self-host coturn | Separate DERP or vendor DERP | Built into the server binary |
| Database | Vendor | PostgreSQL / SQLite | SQLite / PostgreSQL | SQLite embedded |
| Works with no internet at all | No | No | Partially | Yes |
| Deployment | Managed | Docker Compose, 5+ containers | Binary + reverse proxy + DERP | One binary, one YAML line |

Thawr trades breadth for sovereignty and simplicity; `docs/VISION.md`
has the longer version and the non-goals.

## Upgrading

Replace the binary and restart the service:

```
sudo install -m 0755 thawr /usr/local/bin/thawr
sudo systemctl restart thawr-server        # or thawr-client
sudo launchctl kickstart -k system/thawr-client   # macOS
```

The server applies pending database migrations at start; clients keep
their enrollment. A server can refuse clients older than
`min_client_version` in its config; `thawr client status` shows the
server's version and says `client update available` when the server is
ahead. Nothing checks for updates over the internet: the only version
Thawr ever compares against is your own server's.

`thawr server uninstall` and `thawr client uninstall` remove the
service and keep the data; add `--purge --yes` to delete it.

## Building

Requires Go 1.26 or newer. No CGO, no Node.

```
make build      # bin/thawr
make test
make lint       # gofmt, go vet, golangci-lint
make integration  # Linux with CAP_NET_ADMIN
make release VERSION=v0.1.0   # dist/: archives, SHA256SUMS, thawr.rb
make release-verify           # two builds, identical archives
```

Releases are published by CI: push a tag `vX.Y.Z`, or start the
`release` workflow by hand in the Actions tab with the version as input
and it creates the tag on `main` for you. Tags containing a `-`
(`v0.1.0-rc1`) become pre-releases.

## Documentation

| Document | Content |
|---|---|
| `docs/VISION.md` | Problem, users, non-goals, comparison with Tailscale, NetBird, Headscale |
| `docs/ARCHITECTURE.md` | Components, packages, data flows, wire interfaces, dependencies |
| `docs/adr/` | Architecture decision records |
| `docs/THREAT_MODEL.md` | Assets, attackers, mitigations, out of scope |
| `docs/specs/` | One spec per feature with acceptance criteria and tests |
| `TASKS.md` | Backlog and status |
| `CLAUDE.md` | Working agreement for AI-assisted sessions |

## Contributing and security

`CONTRIBUTING.md` has the workflow: semantic commits, one logical
change per commit, `make test lint` clean, Developer Certificate of
Origin sign-off. Pull requests that add cryptographic code are declined
on principle (ADR 0004). Report vulnerabilities privately as described
in `SECURITY.md`, not in a public issue.

Trust in Thawr is explicit. A device trusts the server it enrolled
with (TLS fingerprint) and the WireGuard keys it saw first; after
`thawr client rotate-key` on one device, every other device shows it as
`key changed` and holds it until someone runs `thawr client trust
<name>` there. With the network lock on, the server's word is not
enough: a peer needs a signature from a signing device, held as
`unsigned` until it has one, and a signer's own rotation is signed on
the way. Every control-plane change on the server lands in an
audit log (`thawr admin audit`, the UI, `GET /api/v1/audit`), kept for
`audit.retention_days`. `docs/THREAT_MODEL.md` says what this does and
does not protect against.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
