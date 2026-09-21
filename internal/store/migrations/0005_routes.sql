-- Schema version 5: advertised routes (spec 013). One row per prefix a
-- peer advertises; 0.0.0.0/0 is the exit node. approved_at is NULL until
-- an admin approves the prefix; the rows go with the peer.
CREATE TABLE peer_routes (
    peer_id       TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    prefix        TEXT NOT NULL,
    advertised_at TEXT NOT NULL,
    approved_at   TEXT,
    approved_by   TEXT,
    PRIMARY KEY (peer_id, prefix)
);
