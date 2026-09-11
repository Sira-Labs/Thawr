# Thawr — Vision

Thawr is the cave near Mecca where the Prophet Muhammad ﷺ and Abu Bakr
found shelter during the Hijra: hidden, protected, reachable only by those
who belong. That is what this project builds for machines.

**One binary. No cloud. Works offline.**

## The problem

People who run their own infrastructure want their laptops, servers,
phones and home machines to reach each other securely from anywhere. The
tools that solved this well (Tailscale, NetBird, Firezone) solved it as
cloud services: the coordination server, the identity provider and the
relay fleet belong to the vendor. Self-hosting them is either an
afterthought (Headscale re-implements Tailscale's control protocol and
chases its changes), a multi-container deployment with an external
identity provider as a hard requirement, or gated behind a license.

The result: a homelab owner who wants a private network ends up depending
on someone else's uptime, someone else's identity service and someone
else's terms, or spends a weekend wiring up five containers.

## Who this is for

- Homelab owners with a VPS or a router that can run one process.
- Small teams (2–50 people) that need SSH, internal web apps and shared
  services reachable without exposing them to the internet.
- Organisations that cannot or will not depend on a vendor cloud:
  regulated environments, air-gapped labs, on-premises-only policies,
  sovereignty requirements.

## What Thawr is

A self-hosted private network built on WireGuard.

- One binary, `thawr`, that runs as the server (control plane, STUN,
  relay), as the client on every device, and as the admin CLI.
- Peers connect directly whenever NAT allows and fall back to the relay
  built into the server. Either way traffic is end-to-end encrypted
  between peers; the relay forwards opaque packets.
- Local users and one-time enrollment tokens are the identity system. An
  OIDC provider can be plugged in; it is never required.
- Access is governed by a YAML policy file the user keeps in git. Default
  deny.
- Everything the server needs is in one directory: a SQLite database, its
  WireGuard key, its TLS certificate. Back it up with `cp`.
- Phones use the official WireGuard app; the admin exports a config as a
  QR code.
- It works with the internet cable pulled: no license check, no update
  ping, no external DNS, no certificate authority required.

## What Thawr deliberately is not

- Not a cryptography project. WireGuard does the tunnel, Go's standard
  library and `x/crypto` do hashing. Thawr never implements a primitive.
- Not a Layer-2 network. No broadcast, no bridging, no VXLAN.
- Not a SaaS. There is no hosted control plane and there will not be one.
- Not a mobile app vendor. v1 has no native iOS or Android client.
- Not a replacement for a firewall on the hosts it connects. Thawr
  controls who can reach what over the overlay; it does not manage the
  host's other interfaces.
- Not a Tailscale protocol re-implementation. Thawr has its own control
  protocol and does not aim for compatibility with the Tailscale client.

## How Thawr differs

| | Tailscale | NetBird | Headscale | Thawr |
|---|---|---|---|---|
| Control plane | Vendor cloud | Vendor cloud or self-host (multi-service) | Self-host, re-implements Tailscale protocol | Self-host, own protocol, one process |
| Identity | External IdP required | External IdP required (self-host bundles Zitadel/Dex) | Uses Tailscale clients + OIDC or pre-auth keys | Local users + tokens; OIDC optional |
| Relay | Vendor DERP fleet | Vendor TURN or self-host coturn | Needs separate DERP or vendor DERP | Built into the server binary |
| Database | Vendor | PostgreSQL / SQLite | SQLite / PostgreSQL | SQLite embedded, no options |
| Works offline (no internet at all) | No | No | Partially | Yes |
| Deployment | Managed | Docker Compose, 5+ containers | Binary + reverse proxy + DERP | One binary, one YAML line |
| Client | Vendor binary | Own binary | Tailscale's binary | Own binary, embedded UI |

Thawr trades breadth for sovereignty and simplicity. It will have fewer
features than Tailscale for a long time. The features it has must work
without asking anyone for permission.

### An identity layer for agents, not an IPsec replacement

IPsec authenticates network segments or gateways, never workloads. An
agent running in plant A that talks to a service in plant B is, to
IPsec, "an IP from subnet A", and every process on that host looks the
same. Agents need identity per workload:

- **Who are you?** A cryptographic identity per agent or service, not
  per host, issued and rotated automatically.
- **What may you do?** Policy at the level "agent X may reach service Y
  on port Z", not "subnet A may reach subnet B".
- **Who did what?** An audit log keyed by agent identity, not by source
  IP.

That is zero trust at the workload level (the SPIFFE/SPIRE idea), and
it is what Thawr delivers: a WireGuard tunnel per agent with its own
key, a control plane that issues the identity, ACLs per peer, an audit
log that names the peer, and a network lock in which the owner's own
key, not the server, vouches for each identity. It runs *over* an
existing IPsec tunnel between sites; double encryption is inelegant but
harmless, and nothing in the firewall landscape has to change. The
enterprise story is therefore not "replaces IPsec" but "adds an
identity layer for agents on top of what you have", which IT security
approves more readily because it takes nothing away.

## Principles

1. Sovereign first: the user owns the server, the data, the keys, the
   policy. Nothing phones home.
2. Simplicity is a feature: one binary, one config file, one policy file,
   one data directory. If a feature needs a second service, it waits.
3. Boring security: WireGuard, TLS, argon2id, SQLite. No novelty.
4. Every peer is an identity, not a user: humans, servers and agents are
   first-class from the first commit so workload identity needs no
   redesign.
5. Readable over clever: someone auditing this for their organisation
   should be able to read the whole control plane in an afternoon.
