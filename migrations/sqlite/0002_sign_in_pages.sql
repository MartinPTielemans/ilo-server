-- How many codes this sign-in mailed: the first, and one resend.
ALTER TABLE sign_ins ADD COLUMN codes_sent INTEGER NOT NULL DEFAULT 0;
-- The redirect back to the app, with its code, which the done page follows.
ALTER TABLE sign_ins ADD COLUMN finished_url TEXT;
-- The passkey is offered once, after the account's first sign-in.
ALTER TABLE accounts ADD COLUMN passkey_offered INTEGER NOT NULL DEFAULT 0;
