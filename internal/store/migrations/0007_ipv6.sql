-- Schema version 7: the IPv6 overlay (spec 015). peers.ipv6 has existed
-- since version 1 and is filled at server start from the IPv4 address;
-- it is unique like ipv4 (NULLs are allowed until then).
-- ipv6_capable records whether the peer's client asked for IPv6, so
-- older clients keep getting an IPv4-only netmap.
CREATE UNIQUE INDEX peers_ipv6 ON peers(ipv6);
ALTER TABLE peers ADD COLUMN ipv6_capable INTEGER NOT NULL DEFAULT 0;
