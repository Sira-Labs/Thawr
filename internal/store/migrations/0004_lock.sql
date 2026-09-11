-- Schema version 4: network lock signatures (spec 012). peer_id is a
-- peer id or 'hub'; the lock record itself lives in meta under
-- lock_record. No foreign key: the hub has no peers row, and a peer's
-- rows are removed with the peer.
CREATE TABLE peer_signatures (
    peer_id    TEXT NOT NULL,
    public_key TEXT NOT NULL,
    signer_key TEXT NOT NULL,
    signature  TEXT NOT NULL,
    signed_at  TEXT NOT NULL,
    PRIMARY KEY (peer_id, public_key, signer_key)
);
