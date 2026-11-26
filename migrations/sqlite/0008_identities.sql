-- Another provider's account that signs in to an ilo account: Google's, by its `sub`, which
-- stays when the address at Google changes. Nothing else of the provider's is kept.
CREATE TABLE identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (provider, subject)
);
CREATE INDEX identities_account ON identities (account_id);
-- A sign-in's leg at Google: the state, nonce and PKCE verifier it sent, for the one answer.
ALTER TABLE sign_ins ADD COLUMN google_state TEXT;
ALTER TABLE sign_ins ADD COLUMN google_nonce TEXT;
ALTER TABLE sign_ins ADD COLUMN google_verifier TEXT;
-- A Google account waiting to be linked to the address's account once its mailed code is in.
ALTER TABLE sign_ins ADD COLUMN google_subject TEXT;
-- Set once the account removes its Google sign-in: Google then links to it again only with the
-- address's mailed code, even where Google holds the mailbox.
ALTER TABLE accounts ADD COLUMN google_removed INTEGER NOT NULL DEFAULT 0;
