-- Schema version 9: relay nodes in the netmap (spec 016).
-- relay_capable records whether the peer's client said it can use
-- standalone relay nodes, so older clients keep getting a netmap
-- without relays and without tickets.
ALTER TABLE peers ADD COLUMN relay_capable INTEGER NOT NULL DEFAULT 0;
