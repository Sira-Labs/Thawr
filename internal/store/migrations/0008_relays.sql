-- Schema version 8: standalone relay nodes (spec 016). A relay is not a
-- peer: it has its own table, its own one-time tokens, and the tickets
-- devices present to it. Secrets, tokens and tickets are stored as
-- SHA-256 hashes only.

CREATE TABLE relays (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    url             TEXT NOT NULL,
    tls_fingerprint TEXT NOT NULL,
    secret_hash     TEXT NOT NULL UNIQUE,
    version         TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    last_seen_at    TEXT
);

CREATE TABLE relay_tokens (
    id               TEXT PRIMARY KEY,
    secret_hash      TEXT NOT NULL UNIQUE,
    relay_name       TEXT,
    created_by       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    used_at          TEXT,
    used_by_relay_id TEXT REFERENCES relays(id) ON DELETE SET NULL
);
CREATE INDEX relay_tokens_expires_at ON relay_tokens(expires_at);

CREATE TABLE relay_tickets (
    ticket_hash TEXT PRIMARY KEY,
    peer_id     TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    relay_id    TEXT NOT NULL REFERENCES relays(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);
CREATE INDEX relay_tickets_peer ON relay_tickets(peer_id);
CREATE INDEX relay_tickets_relay ON relay_tickets(relay_id);
CREATE INDEX relay_tickets_expires_at ON relay_tickets(expires_at);
