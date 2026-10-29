-- One row an address, so taking one of its codes for the hour is a single
-- statement that sign-ins asking at once can't all get past. The hour starts
-- at the first code sent after the last hour ended.
DROP TABLE code_mailings;
CREATE TABLE code_mailings (
    email TEXT PRIMARY KEY,
    hour_started_at INTEGER NOT NULL,
    sent INTEGER NOT NULL
);
