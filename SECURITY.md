# Security policy

Thawr connects machines that their owners want to keep private, so a
vulnerability report is the most valuable contribution this project can
receive. Thank you for taking the time.

## Supported versions

Only the latest release on the [Releases page](https://github.com/Sira-Labs/Thawr/releases)
receives fixes. Pre-releases (`v0.1.0-rcN`) are supported until the
next one is published.

## Reporting a vulnerability

Please do not open a public issue for anything that could be a security
problem. Use one of these channels instead:

1. **GitHub private vulnerability reporting**: the *Report a
   vulnerability* button under the repository's *Security* tab opens a
   draft advisory that only the maintainer can read.
2. **Email**: the address on the maintainer's GitHub profile
   ([@Sira-Labs](https://github.com/Sira-Labs)). Put `[thawr
   security]` in the subject.

Include the version (`thawr version --json`), the platform, what you
observed, and how to reproduce it. A proof of concept is welcome; a
working exploit against someone else's network is not.

You can expect an acknowledgement within 72 hours and a first
assessment within a week. Fixes ship as a new release with a GitHub
Security Advisory that credits the reporter unless they prefer to stay
anonymous. Please give the project 90 days before publishing details.

## Scope

In scope: everything in this repository, in particular the control
plane (`internal/control`, `internal/api`), enrollment and token
handling, policy enforcement (`internal/wg`, the userspace filter), the
relay, STUN, the admin UI and the client's local socket API.

Out of scope: WireGuard itself and `wireguard-go` (report upstream),
vulnerabilities that need root on a peer already (root on a peer owns
that peer by design; see `docs/THREAT_MODEL.md`), and findings against
deployments that run with the documented protections turned off.

## What Thawr does to stay boring

- No cryptography of its own: WireGuard for the tunnel, Go's `crypto/*`
  and `golang.org/x/crypto` for hashing and password storage.
- Keys, node secrets, tokens and password hashes are never logged; logs
  carry key fingerprints only.
- Release binaries are built reproducibly by CI from a tag and ship
  with `SHA256SUMS`; `make release-verify` proves two builds are
  byte-identical.
- `govulncheck` runs on every push and pull request.

`docs/THREAT_MODEL.md` lists the assets, the attackers Thawr defends
against and, just as important, the ones it does not.
