-- Each code mailed, by address, for an hour: an address gets a few an hour
-- however many sign-ins ask for one.
CREATE TABLE code_mailings (
    email TEXT NOT NULL,
    sent_at BIGINT NOT NULL
);
CREATE INDEX code_mailings_email ON code_mailings (email, sent_at);
