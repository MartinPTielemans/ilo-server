-- ilo's daily usage count (POST /v1/daily): how many counts came on each UTC day, as days since
-- 1970-01-01, for each set of fields a count carries. Nothing that tells copies apart: no address,
-- no user agent and no time of day.
CREATE TABLE daily_counts (
    day BIGINT NOT NULL,
    version TEXT NOT NULL,
    channel TEXT NOT NULL,
    os TEXT NOT NULL,
    os_major BIGINT NOT NULL,
    chip TEXT NOT NULL,
    first_run BIGINT NOT NULL,
    weekly BIGINT NOT NULL,
    monthly BIGINT NOT NULL,
    count BIGINT NOT NULL,
    PRIMARY KEY (day, version, channel, os, os_major, chip, first_run, weekly, monthly)
);
