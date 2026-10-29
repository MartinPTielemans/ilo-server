CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

-- One pending code per address; a new one replaces it.
CREATE TABLE sign_in_codes (
    email TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL,
    sent_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE passkeys (
    credential_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    passkey TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX passkeys_account ON passkeys (account_id);

-- An authorization request between /authorize and its redirect.
CREATE TABLE sign_ins (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    state TEXT,
    nonce TEXT,
    code_challenge TEXT NOT NULL,
    scope TEXT NOT NULL,
    email TEXT,
    account_id TEXT REFERENCES accounts (id) ON DELETE CASCADE,
    ceremony TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE authorization_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    nonce TEXT,
    code_challenge TEXT NOT NULL,
    scope TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);
CREATE INDEX devices_account ON devices (account_id);

CREATE TABLE tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE INDEX tokens_device ON tokens (device_id);

CREATE TABLE signing_keys (
    id TEXT PRIMARY KEY,
    private_key TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- An account's sync data: its birthday, its version counter and its keystore key.
CREATE TABLE sync_stores (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    birthday TEXT NOT NULL,
    version INTEGER NOT NULL,
    keystore_key BLOB NOT NULL
);

-- `entity` is the SyncEntity as the server serves it; its specifics are the
-- client's bytes, encrypted when the account has a passphrase.
CREATE TABLE sync_entities (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    data_type INTEGER NOT NULL,
    version INTEGER NOT NULL,
    parent_id TEXT,
    deleted INTEGER NOT NULL,
    client_tag_hash TEXT,
    server_tag TEXT,
    entity BLOB NOT NULL,
    PRIMARY KEY (account_id, id)
);
CREATE INDEX sync_entities_updates ON sync_entities (account_id, data_type, version);
CREATE INDEX sync_entities_children ON sync_entities (account_id, parent_id);
