# Spec 012 — Network lock

Sprint 3. Depends on: 003 (netmap sync), 011 (key pinning, audit log).
Packages: new `internal/lock` (records, signatures), `internal/store`
(`peer_signatures`, lock record), `internal/control` (lock service,
signed rotations), `internal/api` (lock RPCs, REST lock view),
`internal/client` (verification, pinned lock record, signing),
`cmd/thawr` (`client lock`, `admin lock`, status), `web/`.

## Goal

After spec 011 a client holds a *changed* key, but it still trusts the
first key it sees and any new peer under a new name. A compromised
server can therefore insert a fresh attacker device, or hand a freshly
enrolled device a substituted hub, and nothing objects. The network
lock makes key distribution require a signature the server does not
hold: an Ed25519 lock key on a device the owner controls signs each
peer record `(id, name, WireGuard public key)`; the server only stores
and forwards signatures; a client with the lock enabled applies only
signed peers and holds the rest. The same signature lets a legitimate
key rotation pass on every other device without the manual `trust`
step 011 introduced. In the words of the vision: the network, not the
server, vouches for an identity.

## User story

As the owner I run `thawr client lock init` on my laptop once. From
then on a device that enrols shows up on every other device as
`unsigned` and cannot talk to anyone until I run `thawr client lock
sign <name>` on the laptop, after checking that the fingerprint it
prints matches what the new device shows in its own status. When I
rotate the laptop's key, my desktop accepts the new key by itself,
because the laptop signed it. If my server were compromised, a peer it
invents has no signature and no device talks to it; a lock record it
forges is rejected because no lock key signed it.

## Commands

```
thawr client lock init                # create lock.key here, sign hub and every visible peer, enable
thawr client lock status              # enabled, signers, unsigned peers, this device's role
thawr client lock sign <name>... | --all   # sign peers (hub is "hub"); prints fingerprints
thawr client lock key                 # create lock.key on a future signer, print its public key
thawr client lock add-signer <name>   # on a current signer: add that device's lock key to the set
thawr client lock disable             # on a current signer: signed record that turns the lock off

thawr admin lock                      # lock view over the admin socket (or GET /api/v1/lock)
thawr admin peer list                 # gains a SIGNED column while the lock is on
```

`client status` header with the lock on:

```
WireGuard: kernel · thawr0 · listen 41820 · NAT: cone (...) · DNS: .thawr via resolved · lock: on (signer) · 1 unsigned: thawr client lock sign new-box
```

## Behaviour

### Records and signatures (`internal/lock`)

- Lock keys are Ed25519 from `crypto/ed25519`. No cryptography is
  implemented here; the package encodes records and calls the standard
  library. Public keys are base64 like WireGuard keys; fingerprints are
  the first 8 hex characters of SHA-256, as everywhere else.
- A **peer record** is the canonical byte string
  `"thawr/peer/v1\n" || u16len(id) || id || u16len(name) || name ||
  u16len(key) || key` with the 32 raw key bytes. The name is part of
  the record: `<name>.thawr` is what people type, so a renamed peer
  must be signed again, and an attacker who moves a victim's name onto
  an already-signed device gains nothing. The hub is the record
  `("hub", "hub", hub key)`.
- A **lock record** is `"thawr/lock/v1\n" || u64 generation || u8
  disabled || u16 count || (u16len(key) || key || u16len(peer id) ||
  peer id)*` with signers sorted by key, signed by one lock key.
  Acceptance (`lock.Accept(current, next, sig)`): with no current
  record the first one is accepted as is (first contact, the same
  trust the enrolment already extends); otherwise `next.generation`
  must exceed the current one and the signature must verify against a
  key of the **current** set. A record with `disabled` set turns the
  lock off and must be signed the same way, so the server cannot turn
  the lock off on its own; it keeps the signer set, so only a signer
  can turn the lock on again. A record without signers ends its
  lineage: the next record starts over under the first-contact rule.

### Server

- Migration `0004_lock.sql`: `peer_signatures(peer_id, public_key,
  signer_key, signature, signed_at)` with the primary key `(peer_id,
  public_key, signer_key)`; `peer_id` is a peer id or `hub`. The lock
  record and its signature live in `meta` under `lock_record`.
- `SetLock(record, signature, signatures[])`: any node may send the
  first record; later ones must pass `lock.Accept` against the stored
  one. The optional signatures are by the caller's key in the new
  record and are verified and stored in the same transaction, so a
  record and the signatures that go with it reach every device in one
  netmap. Stored, generation bumped, audit `lock.set` (actor
  `peer:<name>`, details generation, signers, disabled) and one
  `peer.sign` per attached signature.
- `SignPeer(peer_id, public_key, signer_key, signature)`: the caller's
  peer id must be a signer of the current record with that lock key,
  the signature must verify over the record of the named peer's
  **current** key (or the hub key); stored, generation bumped, audit
  `peer.sign` (target peer id, details name, key fingerprint, signer
  fingerprint). A delete removes the peer's rows.
- `ListLockPeers`: every peer with id, name, key and whether the
  current key carries a valid signature, plus the hub. Answered only to
  a peer whose id is a signer in the current record; everyone else gets
  `PermissionDenied`. A signer needs the whole registry, not the slice
  its policy shows it, and the lock record, signed by a lock key, is
  what names it a signer.
- `RotateKey` accepts an optional `(signer_key, signature)` over the
  new key; when the caller is a signer with that key and the signature
  verifies, the row is written in the rotation's transaction, so the
  new key is signed the moment other devices see it.
- Netmaps carry the current lock record and, per peer, for the hub and
  for the receiver itself (`SelfInfo.signatures`), the signatures over
  the current key. `Build` reads all signatures in one query per
  netmap.
- `GET /api/v1/lock` (authenticated): enabled, generation, signers
  (fingerprint, peer name), unsigned peers. `peers[].signed` is true or
  false while the lock is on and absent otherwise.

### Client

- `lock.key` in the state dir (0600), created by `lock init` or
  `lock key`, removed by `client down --forget`. Its public key is
  reported in every `SyncRequest`, so the server can list it for
  `add-signer`.
- `pins.json` gains the pinned lock record. On every netmap: none
  pinned and none offered → lock off; offered and none pinned → pin it
  and log which signers now vouch for the network; both → `Accept`,
  replace the pin on success, keep it and report `lock.rejected` on
  failure; **pinned but none offered → still on** with the pinned set,
  until a signed `disabled` record arrives.
- With the lock on, verification runs before the 011 pin check: the hub
  and every agent peer need a signature by a key of the pinned set that
  verifies over their current record; the rest are held with reason
  `unsigned` (path `unsigned`), which means no WireGuard peer, no name,
  no route, no probing, exactly like `key_changed`. Signed entries are
  accepted into the pins (`Pins.Accept`) before the pin check, so a
  signed rotation and a signed new peer pass without `trust`. Static
  (`via_hub`) peers stay out of scope as in 011: they have no WireGuard
  peer on the client and are reached through the hub, whose key is
  signed.
- `trust` still works for `key_changed` entries when the lock is off;
  with the lock on it answers that unsigned peers need `lock sign`.
- Signing runs inside the daemon over the local API (`POST /lock/init`,
  `/lock/sign/{name}`, `/lock/key`, `/lock/add-signer/{name}`,
  `/lock/disable`): it holds the gRPC client, the netmap and the key.
  `init` sends the record **together with** its signatures over the
  hub, itself and every peer the daemon currently sees, stored in one
  transaction, so enabling never cuts a working network; peers outside
  the signer's policy view stay unsigned until `lock sign`, which
  lists them all through `ListLockPeers`. Every signing
  command prints the fingerprints it signed; comparing them with
  `thawr client status` on the other device is the human step that
  gives the signature its meaning. `rotate-key` on a signer signs its
  own new key.
- Status: `lock{enabled, signer, has_key, generation, signers[],
  rejected, self_signed}`; `held[].reason` is `key_changed` or
  `unsigned`; the header appends `· lock: on (signer)` / `· lock: on` /
  `· lock: on, this device unsigned` / `· lock: off` and, when
  something is unsigned, `· N unsigned: thawr client lock sign
  <names>`. `client up` logs a hint while its own record is unsigned;
  `client lock status` prints the record, the signers and the holds.

## Acceptance criteria

1. Two clients see each other. `lock init` on A: B's status shows
   `lock: on`, both keep their paths, `admin lock` lists A as signer,
   `admin audit` has `lock.set` and one `peer.sign` per peer and hub.
2. C enrols: A and B show C `unsigned`, C has no WireGuard peer on
   either and `c.thawr` does not resolve. `lock sign c` on A: within one
   netmap both apply C. `lock sign` on B (not a signer) fails.
3. `rotate-key` on A: B applies the new key without `trust`.
   `rotate-key` on C: A and B hold C `unsigned` until `lock sign c`.
4. A record signed by a key outside the pinned set, or with a stale
   generation, is rejected; the client keeps its pinned set and reports
   `lock.rejected`. A netmap without a record keeps the lock on.
5. `lock disable` on A: B's lock turns off, pins (011) apply again.
   `lock add-signer b` after `lock key` on B: B can sign.
6. `ListLockPeers` answers a signer and refuses a non-signer;
   `SignPeer` refuses a non-signer, a wrong key and a bad signature.
7. `peers[].signed` and the SIGNED column reflect the current key: a
   rotation without signature flips a peer to unsigned.

## Test cases

- `internal/lock`: golden canonical bytes for both records, tampering
  with each field breaks verification, acceptance rules (first record,
  replay, outside key, disabled).
- `internal/store`: signatures put/list/delete, lock record round trip.
- `internal/control`: `TestLockSetAcceptsOnlySignedSuccessors`,
  `TestSignPeerRequiresSigner`, `TestRotateKeyStoresSignature` (which
  also checks the netmap carries the signatures).
- `internal/api`: `TestLockRPCs` (`ListLockPeers` gating, `SetLock`,
  `SignPeer`, signatures and record in `Sync`), `TestLockEndpoint`
  (REST lock view and `signed`).
- `internal/client`: unsigned peer held then signed and applied, signed
  rotation passes without trust, outside-key record rejected, dropped
  record keeps the lock, disabled record turns it off, `lock.key` round
  trip, status and schema.
- `cmd/thawr`: `client lock` subcommands against a fake socket, status
  header and table, `admin lock`, `admin peer list` column.
- `tests/lock_test.go` (integration, Linux): criteria 1 to 3.

## Out of scope

- Removing a signer (`lock remove-signer`); a disable and a fresh init
  covers it for v1.
- Signatures for static peers and phones; their traffic ends at the
  hub, whose key is signed.
- Quorum (more than one signature per record) and key rotation of lock
  keys themselves.
- Short-lived keys with automatic rotation and expiry, and binding an
  agent identity to a process rather than a host: phase-2 candidates
  from the positioning note in VISION.md.
