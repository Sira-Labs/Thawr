# Spec 014 — Operations: backup and restore, metrics, ACME

Sprint 6. Depends on: 001 (bootstrap, data_dir, TLS), 002 (admin
socket, REST), 005 (relay counters), 007 (status), 011 (audit log).
Packages: `internal/store` (snapshot, audit count), `internal/server`
(data_dir lock, archive, restore, certificate selection, metrics
listener), `internal/flock` (new, moved from `internal/client`),
`internal/metrics` (new), `internal/api` (socket-only routes),
`internal/control` (audit action, login counter), `internal/stun`
(counters), `internal/client` (pinned SNI), `internal/config`
(`tls.mode: acme`, `metrics`), `cmd/thawr` (`admin backup`, `server
restore`).

## Goal

A server holds the whole network: the registry, the keys that make
enrolled devices trust it, the policy and the audit log. Losing the
host must not mean re-enrolling every device, and watching it must not
mean reading logs. Three things, none of which sends anything off the
host unless the owner turns it on:

1. **Backup and restore.** One command on a running server writes one
   archive; one command on a fresh host (stopped server) turns that
   archive back into the same network. Devices reconnect without
   noticing, because the server's WireGuard key and its pinned TLS
   certificate come back with the database.
2. **Metrics.** A Prometheus text endpoint with counts and gauges only:
   never a key, a peer name, an address or a token.
3. **ACME.** An optional browser-trusted certificate for the admin UI
   from an ACME CA (Let's Encrypt), without breaking the pinning every
   client relies on. The self-signed certificate stays the default.

## User story

As the owner I run `thawr admin backup --out /backup/thawr.tar.gz`
from cron on the server. The VPS dies. On a new VPS I install the same
or a newer `thawr`, run `thawr server restore /backup/thawr.tar.gz`,
point the DNS name in `public_addr` at the new address and start the
service. `admin peer list` shows every device, and my laptop's `client
status` says connected again within a minute; nobody re-enrolled.

I add `metrics: {listen: 127.0.0.1:9469}` and point the Prometheus on
the same host at it, so I get an alert when no peer has been online
for ten minutes. I switch `tls.mode` to `acme` with my email, and the
admin UI opens in a browser without a warning, while every client
keeps the fingerprint it enrolled with.

## Commands

```
thawr admin backup [--out FILE|-]          # archive of the running server, mode 0600; audit backup.create
thawr server restore FILE [--config PATH] [--force]
                                           # stopped server only; writes data_dir (and config/policy if absent)
curl --unix-socket /var/lib/thawr/admin.sock http://thawr/metrics
curl http://127.0.0.1:9469/metrics         # with metrics.listen set
```

Config (new keys, all optional):

```yaml
tls:
  mode: acme                 # self-signed (default) | file | acme
  email: ops@example.org     # acme: required, the CA's contact
  domain: vpn.example.org    # acme: defaults to the host of public_addr; must be a DNS name
  acme_directory: ""         # acme: CA directory URL; empty is Let's Encrypt production
metrics:
  listen: ""                 # host:port of a plain-HTTP /metrics listener; empty is off
```

## Behaviour

### data_dir lock

- `Server.Run` takes an exclusive, non-blocking lock on
  `data_dir/thawr.lock` right after creating `data_dir`, before the
  database is opened, and holds it for the process lifetime. A second
  server on the same `data_dir` exits at once with "another thawr
  server is using <data_dir>"; until now it opened the database and
  ran migrations before failing on the WireGuard interface or a port.
- The lock is the client's instance lock moved into `internal/flock`
  (`flock` on Unix, `LockFileEx` on Windows). The file is never
  removed, for the reason the client's comment gives. `server restore`
  takes the same lock.

### Backup

- `GET /api/v1/backup` is registered on the **admin socket only**. The
  HTTPS listener never serves it, for any role, because the archive
  holds `server.key` and the TLS private key; a web admin who wants a
  backup needs shell access to the server, the same as for
  `server.key` today.
- The server snapshots the database with `VACUUM INTO` a temporary file
  in `data_dir` (consistent, compacted, the method ADR 0002 names).
  The single connection is held for the snapshot, so other requests
  wait for it; at the sizes Thawr targets that is well under a second.
  The archive is streamed as `application/gzip` and the temporary file
  is removed afterwards, also on error.
- **Archive format** (`tar.gz`, format 1):
  - `manifest.json`: `format`, `thawr_version`, `schema_version`,
    `created` (RFC 3339 UTC), `server_key_fingerprint` (the meta
    value), `tls_mode`, and `files[] {path, size, sha256}` for every
    other entry.
  - `thawr.db`: the snapshot.
  - `server.key`.
  - `tls/cert.pem`, `tls/key.pem` when `tls.mode` is `self-signed` or
    `acme` (the pinned certificate); in `file` mode the operator's
    files are outside `data_dir` and not included, which the manifest
    records.
  - `acme/…`: the ACME cache (account key, certificates) when present.
  - `config/server.yaml` and `config/policy.yaml`: copies of the files
    the running server was started with, when it can read them.
  - Every entry has mode 0600 in the archive and no owner names.
- `thawr admin backup` streams the response without the admin client's
  30-second timeout and 4 MiB cap. `--out FILE` (default
  `thawr-backup-<YYYYMMDDTHHMMSSZ>.tar.gz` in the working directory)
  is written through a temporary file with mode 0600 and renamed into
  place; on Windows the file gets the admin-only ACL. `--out -` writes
  to standard output. It prints the path, the size and the sha256.
- Audit `backup.create`, actor as for every socket call (`local`),
  target the archive's suggested name, details `sha256` of the archive
  and `peers` (count). The row is written after the archive was
  produced, in its own transaction; a failed backup leaves no row. The
  snapshot is taken first, so an archive never contains its own
  `backup.create` row.

### Restore

`thawr server restore FILE` runs on the host, as root, with the server
stopped:

1. Load the config (`--config`, as for `thawr server`). When the
   config file does not exist yet (fresh host), use the archive's
   `config/server.yaml`, and fail if the archive has none.
2. Refuse when a server is running: the admin socket accepts a
   connection, or `data_dir/thawr.lock` is held. Hold the lock until
   the restore ends.
3. Read the archive into a temporary directory next to `data_dir`.
   Refuse when the manifest is missing, the format is not 1, a file is
   missing, extra, or its size or sha256 differ, a path is absolute or
   contains `..`, or `schema_version` is newer than this binary
   supports ("backup schema version N is newer than this binary;
   install thawr X or newer").
4. Refuse a non-empty `data_dir` unless `--force`. With `--force` the
   existing directory is renamed to `<data_dir>.pre-restore-<UTC
   timestamp>` and kept; restore never deletes data.
5. Move the files into a new `data_dir` (0700; `server.key`,
   `tls/key.pem`, the ACME cache 0600; Windows: the admin-only ACL as
   at bootstrap).
6. Open the restored database once: migrations run (an archive from an
   older release is upgraded here), and the server key in `server.key`
   must match `server_key_fingerprint` in meta, as at every start.
7. Write `config/server.yaml` to the `--config` path and
   `config/policy.yaml` to `policy_file` only when no file exists
   there; an existing file is left alone and reported as "kept".
8. Print what was restored: peers, schema version (and whether it was
   migrated), TLS fingerprint, the paths written or kept, and the
   reminder that `public_addr` must resolve to this host before
   clients can reconnect.

The restored server presents the same pinned certificate and the same
WireGuard key, so enrolled clients reconnect without any step on their
side once the address resolves to the new host. Peer endpoints and
paths are learnt again from the clients, as after any restart.

### Metrics

- `GET /metrics` on the admin socket, and, when `metrics.listen` is
  set, on a separate plain-HTTP listener that serves `/metrics` and
  nothing else (404 for every other path). The listener is off by
  default; the docs recommend a loopback address or a firewall, since
  it has no authentication.
- Prometheus text exposition format 0.0.4, written by a small
  `internal/metrics` package (no client library, no new dependency).
- **Catalogue:**

  | Metric | Type | Labels | Source |
  |---|---|---|---|
  | `thawr_build_info` | gauge (1) | `version` | build |
  | `thawr_uptime_seconds` | gauge | | server start |
  | `thawr_peers` | gauge | `kind` | store |
  | `thawr_peers_online` | gauge | | hub and static peers |
  | `thawr_netmap_generation` | gauge | | hub |
  | `thawr_relay_sessions` | gauge | | relay |
  | `thawr_relay_frames_total`, `_bytes_total`, `_drops_total`, `_violations_total` | counter | | relay |
  | `thawr_stun_requests_total` | counter | `result`: `ok`, `ratelimited`, `malformed` | STUN server |
  | `thawr_login_failures_total` | counter | | user service |
  | `thawr_audit_rows` | gauge | | store |

- Label values come from fixed sets (`kind`: `human`, `server`,
  `agent`; `result` as above; `version` is the build string). No
  metric carries a peer name, user name, key, fingerprint, address or
  token, and a test enrols a peer with a distinctive name and asserts
  it does not appear in the scrape.
- Counters start at zero at every server start, as Prometheus expects.

### ACME and certificate selection

- `tls.mode: acme` needs `tls.email` and a DNS name: `tls.domain`, or
  the host of `public_addr` when it is not an IP literal. Validation
  rejects an IP literal with "tls.mode acme needs a DNS name in
  tls.domain or public_addr".
- The server still creates (or loads) the self-signed certificate in
  `data_dir/tls/`, prints its fingerprint and uses it for every
  client. The HTTPS listener chooses the certificate per connection
  from the TLS ServerName (SNI):
  - `thawr-pinned.invalid` (sent by every client from this release on)
    and an empty SNI (older clients dialing an IP literal): the
    self-signed, pinned certificate.
  - The ACME domain, in `acme` mode: the ACME certificate from
    `golang.org/x/crypto/acme/autocert`; challenges are answered over
    TLS-ALPN-01 on the HTTPS port (`acme-tls/1` is added to the
    listener's protocols), so no port 80 is needed. The cache lives in
    `data_dir/acme` (0700). The server requests the certificate once
    at start, in the background, so the first browser does not wait
    for issuance inside its handshake.
  - Any other name: the pinned certificate (in `file` mode, the one
    certificate, as today).
- The ACME certificate renews on its own; renewals never touch the
  pinned certificate, so no client is affected. The pinned certificate
  keeps its ten-year lifetime; rotating it stays out of scope.
- **Client.** `PinnedTLSConfig` and `ProbeFingerprint` set
  `ServerName: thawr-pinned.invalid`. Pinning is unchanged: the leaf's
  sha256 must match, CAs and names are ignored. `.invalid` is reserved
  (RFC 2606), so the name can never belong to a real host.
- **Older clients.** A client from before this release that dials a
  host name sends that name as SNI and, in `acme` mode, would receive
  the ACME certificate and fail its pin. Startup and `server --check`
  therefore warn when `tls.mode` is `acme` and `min_client_version` is
  below `0.2` (and when `listen.https` is not on port 443, where the CA
  validates), and the docs say: upgrade the clients, set
  `min_client_version: "0.2"`, then switch to `acme`. `self-signed`
  and `file` mode behave exactly as before for every client.

## Acceptance criteria

1. A second `thawr server` on the same `data_dir` exits within a
   second with "another thawr server is using …" and leaves the
   database untouched.
2. `thawr admin backup --out b.tar.gz` on a running server with peers,
   a policy and audit rows writes a 0600 archive whose manifest
   checksums match; `admin audit --action backup.create` shows the
   row. The HTTPS listener answers 404 to `GET /api/v1/backup`, for an
   admin session too.
3. `thawr server restore b.tar.gz` into an empty `data_dir` on another
   host, then `thawr server`: `admin peer list` matches the source,
   the printed TLS fingerprint and the server key fingerprint are the
   source's, and a client enrolled against the source reconnects
   without `client up` or `client trust`.
4. Restore refuses: a running server; a non-empty `data_dir` without
   `--force` (with it, the old directory exists afterwards under the
   `pre-restore` name); an archive with one byte changed; a schema
   newer than the binary; a path with `..`.
5. A restored archive from an older schema is migrated during restore
   and the server starts.
6. `/metrics` on the socket and on `metrics.listen` returns the
   catalogue above in valid exposition format; a peer's name, key or
   address never appears in it; `metrics.listen` empty opens no port.
7. In `acme` mode against a staging CA: a browser (or `curl` with the
   system roots) gets a trusted certificate for the domain; `client
   status` on an enrolled client stays connected; a forced renewal
   changes the browser's certificate and not the client's
   fingerprint. In `self-signed` mode the SNI change is invisible.

## Test cases

- `internal/flock`: lock held by one handle, refused for a second,
  released on close (Unix and Windows).
- `internal/server`: `TestDataDirLock` (second `Run` fails fast,
  before `store.Open`).
- `internal/store`: `TestBackupTo` (copy opens, same peers, same
  `schema_version`, the source stays usable); `TestAuditCount`.
- `internal/server`: `TestBackupArchive` (entries, modes, manifest
  checksums, no temporary file left), `TestRestore` (round trip into a
  temp dir, then `Run` on it: same peers, TLS and key fingerprints),
  `TestRestoreRefuses` (table: tampered byte, missing file, extra
  file, `..` path, newer schema, non-empty dir, running lock),
  `TestRestoreForceKeepsOldDir`, `TestRestoreConfigOnlyIfAbsent`.
- `internal/api`: `TestBackupRouteSocketOnly` (404 on the HTTPS mux
  with an admin session, 200 on the local mux), audit row written.
- `cmd/thawr`: `admin backup --out` mode 0600 and output line,
  `--out -`, `server restore` flags and exit codes.
- `internal/metrics`: exposition format golden file, label escaping.
- `internal/server`: `TestMetricsScrape` (golden names and types after
  enrolling a peer named `secret-host-name`, which must not appear),
  `TestMetricsListenerOff`.
- `internal/config`: `TestValidate` rows for `tls.mode: acme` (email
  missing, IP-only public_addr, domain set), `metrics.listen`
  (malformed address).
- `internal/server`: `TestCertificateBySNI` (pinned SNI and empty SNI
  get the self-signed certificate, the domain gets the ACME one, a
  stub stands in for autocert).
- `internal/client`: `TestPinnedDialSendsPinnedSNI` (a server whose
  default certificate differs still verifies through the pinned SNI).
- `internal/server`: `TestACMEModeKeepsClientsOnPinnedCert` (a server
  in acme mode whose CA refuses: the pinned name and no name get the
  pinned certificate, the domain never does), `TestCertSelectorWarm`.
- Issuance against a real CA is the manual checklist step (Let's
  Encrypt staging on the VPS), not a test CI would never run; it was
  checked once against Pebble with TLS-ALPN-01 validation.

## Out of scope

- Encrypting the archive. It is as sensitive as `data_dir` (threat
  model T4); store it on an encrypted volume or encrypt it with your
  own tooling (`age`, `restic`). Thawr does not implement cryptography.
- Scheduled or remote backups, retention, and incremental backups; cron
  and the operator's backup tool do that with `admin backup`.
- Rotating the pinned self-signed certificate.
- ACME over HTTP-01 or DNS-01, and certificates for names other than
  the one domain.
- Authentication on the metrics listener, and push gateways.
- Restoring onto a running server, or merging two networks.
