-- Schema version 6: whether an admin issued a token. Only such a token
-- may take a peer name the policy selects with peer:<name>, checked at
-- enrolment against the policy then in force. Tokens from before this
-- version count as not issued by an admin.
ALTER TABLE enrollment_tokens ADD COLUMN issued_by_admin INTEGER NOT NULL DEFAULT 0;
