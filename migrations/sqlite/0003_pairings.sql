-- A new device asking the account's others for its passphrase, through the
-- relay. Rows stay an hour after they end, emptied, to count requests against
-- the account's limit.
CREATE TABLE pairings (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    requester TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    approver TEXT REFERENCES devices (id) ON DELETE CASCADE,
    -- requested, accepted, revealed, or closed.
    step TEXT NOT NULL,
    -- The pair_request frame the account's other devices get, until it closes.
    request TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX pairings_account ON pairings (account_id, created_at);
