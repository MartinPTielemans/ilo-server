-- Every limit on mailing codes, one row a counter: an address's hour
-- ("address …"), a client's hour ("client …") and the server's day ("all").
-- Taking a code is a single statement on each, which sign-ins asking at once
-- can't all get past, and a window starts at the first code taken after the
-- last one ended.
CREATE TABLE code_limits (
    name TEXT PRIMARY KEY,
    started_at BIGINT NOT NULL,
    sent BIGINT NOT NULL
);
INSERT INTO code_limits (name, started_at, sent)
    SELECT 'address ' || email, hour_started_at, sent FROM code_mailings;
DROP TABLE code_mailings;
