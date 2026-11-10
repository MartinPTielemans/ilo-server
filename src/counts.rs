//! ilo's daily usage count, `POST /v1/daily`: one anonymous count a day from each copy of ilo whose
//! user leaves it on, as `docs/protocol.md` describes. A count carries no ID, so the server keeps
//! only how many came each UTC day with each set of fields. It never keeps or logs the address it
//! came from, its user agent or the time of day.
//!
//! The rows give the numbers: a day's counts are its daily users, the counts flagged `weekly` in an
//! ISO week its weekly users, those flagged `monthly` in a month its monthly users, and those
//! flagged `first` new installs. `ilo-server counts` prints them, and `GET /counts` shows them to
//! whoever has `COUNTS_PASSWORD` (`counts_page.rs`), with each day broken down by the kind of copy
//! that counted: its system, chip, version and channel.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use sqlx::Row as _;

use crate::Shared;

/// A count is a few short fields.
pub const MAX_BODY: usize = 1024;

/// What a copy sends. Fields it doesn't know are ignored, and never stored.
#[derive(Deserialize)]
pub struct Count {
    version: String,
    channel: String,
    os: String,
    os_major: i64,
    chip: String,
    first: bool,
    daily: bool,
    weekly: bool,
    monthly: bool,
}

impl Count {
    /// Only the values ilo sends, so the table holds one row per real combination and nothing a
    /// client could slip in.
    fn valid(&self) -> bool {
        let version = &self.version;
        let version_ok = (1..=16).contains(&version.len())
            && version.split('.').all(|part| {
                !part.is_empty() && part.len() <= 5 && part.bytes().all(|b| b.is_ascii_digit())
            });
        version_ok
            && matches!(self.channel.as_str(), "release" | "nightly")
            && matches!(self.os.as_str(), "macos" | "windows" | "linux")
            && (0..1000).contains(&self.os_major)
            && matches!(self.chip.as_str(), "arm64" | "x64")
            && self.daily
    }
}

pub async fn daily(State(state): State<Shared>, Json(count): Json<Count>) -> StatusCode {
    if !count.valid() {
        return StatusCode::BAD_REQUEST;
    }
    let stored = sqlx::query(
        "INSERT INTO daily_counts \
         (day, version, channel, os, os_major, chip, first_run, weekly, monthly, count) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1) \
         ON CONFLICT (day, version, channel, os, os_major, chip, first_run, weekly, monthly) \
         DO UPDATE SET count = daily_counts.count + 1",
    )
    .bind(crate::db::now().div_euclid(DAY))
    .bind(&count.version)
    .bind(&count.channel)
    .bind(&count.os)
    .bind(count.os_major)
    .bind(&count.chip)
    .bind(i64::from(count.first))
    .bind(i64::from(count.weekly))
    .bind(i64::from(count.monthly))
    .execute(&state.db)
    .await;
    match stored {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(error) => {
            tracing::error!(%error, "a daily count wasn't stored");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

const DAY: i64 = 24 * 60 * 60;

/// What a count says of the copy that sent it, besides its flags.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Kind {
    pub os: String,
    pub os_major: i64,
    pub chip: String,
    pub version: String,
    pub channel: String,
}

/// One row of `daily_counts`, as the report reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tally {
    pub day: i64,
    pub kind: Kind,
    pub first: bool,
    pub weekly: bool,
    pub monthly: bool,
    pub count: i64,
}

/// The rows from `since`, a day number, on.
pub async fn tallies(db: &crate::db::Db, since: i64) -> anyhow::Result<Vec<Tally>> {
    let rows = sqlx::query(
        "SELECT day, os, os_major, chip, version, channel, first_run, weekly, monthly, count \
         FROM daily_counts WHERE day >= $1",
    )
    .bind(since)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(Tally {
                day: row.try_get("day")?,
                kind: Kind {
                    os: row.try_get("os")?,
                    os_major: row.try_get("os_major")?,
                    chip: row.try_get("chip")?,
                    version: row.try_get("version")?,
                    channel: row.try_get("channel")?,
                },
                first: row.try_get::<i64, _>("first_run")? != 0,
                weekly: row.try_get::<i64, _>("weekly")? != 0,
                monthly: row.try_get::<i64, _>("monthly")? != 0,
                count: row.try_get("count")?,
            })
        })
        .collect()
}

/// How far back the report goes, in days: enough for six whole months.
pub const REPORT_DAYS: i64 = 200;

/// Today's day number, as the endpoint stores them.
pub fn today() -> i64 {
    crate::db::now().div_euclid(DAY)
}

/// The numbers `ilo-server counts` prints and `GET /counts` shows, for the days up to a day:
/// daily users and new installs for the last 14 days, weekly users for the last 8 ISO weeks, and
/// monthly users for the last 6 months, each newest first. The current week and month are still
/// filling. The page also breaks each of the 14 days down by kind of copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Numbers {
    /// `YYYY-MM-DD`, users, new installs.
    pub days: Vec<(String, i64, i64)>,
    /// `YYYY-Www`, users.
    pub weeks: Vec<(String, i64)>,
    /// `YYYY-MM`, users.
    pub months: Vec<(String, i64)>,
    /// The same days as `days`: each kind of copy that counted on it, with its users and new
    /// installs, most users first.
    pub kinds: Vec<Vec<(Kind, i64, i64)>>,
}

/// The numbers for the days up to `today`, from the database: the one query the command and the
/// page share, so they can't drift apart.
pub async fn read(db: &crate::db::Db, today: i64) -> anyhow::Result<Numbers> {
    Ok(numbers(&tallies(db, today - REPORT_DAYS).await?, today))
}

/// The numbers the rows `tallies` give for the days up to `today`.
pub fn numbers(tallies: &[Tally], today: i64) -> Numbers {
    let mut days: BTreeMap<i64, (i64, i64)> = BTreeMap::new();
    let mut weeks: BTreeMap<i64, i64> = BTreeMap::new();
    let mut months: BTreeMap<(i64, u32), i64> = BTreeMap::new();
    let mut kinds: BTreeMap<i64, BTreeMap<&Kind, (i64, i64)>> = BTreeMap::new();
    for day in today - 13..=today {
        days.insert(day, (0, 0));
    }
    for week in 0..8 {
        weeks.insert(monday(today) - 7 * week, 0);
    }
    let mut month = month_of(today);
    for _ in 0..6 {
        months.insert(month, 0);
        month = if month.1 == 1 {
            (month.0 - 1, 12)
        } else {
            (month.0, month.1 - 1)
        };
    }
    for tally in tallies {
        if let Some((users, new)) = days.get_mut(&tally.day) {
            let first = if tally.first { tally.count } else { 0 };
            *users += tally.count;
            *new += first;
            let kind = kinds.entry(tally.day).or_default();
            let (users, new) = kind.entry(&tally.kind).or_default();
            *users += tally.count;
            *new += first;
        }
        if tally.weekly
            && let Some(users) = weeks.get_mut(&monday(tally.day))
        {
            *users += tally.count;
        }
        if tally.monthly
            && let Some(users) = months.get_mut(&month_of(tally.day))
        {
            *users += tally.count;
        }
    }
    let kinds = (days.keys().rev())
        .map(|day| {
            let mut list: Vec<(Kind, i64, i64)> = (kinds.get(day).into_iter().flatten())
                .map(|(kind, (users, new))| ((*kind).clone(), *users, *new))
                .collect();
            list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            list
        })
        .collect();
    Numbers {
        kinds,
        days: (days.iter().rev())
            .map(|(day, (users, new))| {
                let (year, month, date) = civil(*day);
                (format!("{year:04}-{month:02}-{date:02}"), *users, *new)
            })
            .collect(),
        weeks: (weeks.iter().rev())
            .map(|(monday, users)| {
                let (year, week) = iso_week(*monday);
                (format!("{year:04}-W{week:02}"), *users)
            })
            .collect(),
        months: (months.iter().rev())
            .map(|((year, month), users)| (format!("{year:04}-{month:02}"), *users))
            .collect(),
    }
}

impl Numbers {
    /// As `ilo-server counts` prints them.
    pub fn text(&self) -> String {
        let mut out = String::from("Daily users (UTC)      users     new\n");
        for (day, users, new) in &self.days {
            out += &format!("  {day}         {users:>7} {new:>7}\n");
        }
        out += "Weekly users (ISO)     users\n";
        for (week, users) in &self.weeks {
            out += &format!("  {week}             {users:>7}\n");
        }
        out += "Monthly users          users\n";
        for (month, users) in &self.months {
            out += &format!("  {month}              {users:>7}\n");
        }
        out
    }
}

/// The Monday of `day`'s ISO week. Day 0, 1970-01-01, was a Thursday.
fn monday(day: i64) -> i64 {
    day - (day + 3).rem_euclid(7)
}

fn month_of(day: i64) -> (i64, u32) {
    let (year, month, _) = civil(day);
    (year, month)
}

/// The ISO year and week of the week starting on the Monday `monday`: its Thursday's year, and
/// that Thursday's place in it.
fn iso_week(monday: i64) -> (i64, i64) {
    let thursday = monday + 3;
    let (year, _, _) = civil(thursday);
    let first_day = days_from_civil(year, 1, 1);
    (year, (thursday - first_day) / 7 + 1)
}

/// The proleptic Gregorian date of a day number (Howard Hinnant's `civil_from_days`).
fn civil(day: i64) -> (i64, u32, u32) {
    let z = day + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let date = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, date)
}

/// The day number of a date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: u32, date: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(date) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tally(day: i64, first: bool, weekly: bool, monthly: bool, count: i64) -> Tally {
        Tally {
            day,
            kind: Kind::default(),
            first,
            weekly,
            monthly,
            count,
        }
    }

    #[test]
    fn dates_and_iso_weeks_follow_the_calendar() {
        assert_eq!(civil(0), (1970, 1, 1));
        let day = days_from_civil(2026, 11, 6);
        assert_eq!(civil(day), (2026, 11, 6));
        // 2026-11-06 is a Friday in ISO week 45.
        assert_eq!(civil(monday(day)), (2026, 11, 2));
        assert_eq!(iso_week(monday(day)), (2026, 45));
        // 2027-01-01 is a Friday, in 2026's week 53.
        let new_year = days_from_civil(2027, 1, 1);
        assert_eq!(iso_week(monday(new_year)), (2026, 53));
        // 2024-12-30 is a Monday, in 2025's week 1.
        assert_eq!(iso_week(days_from_civil(2024, 12, 30)), (2025, 1));
        assert_eq!(civil(days_from_civil(2024, 2, 29)), (2024, 2, 29));
    }

    #[test]
    fn the_report_adds_users_by_day_week_and_month() {
        let today = days_from_civil(2026, 11, 6);
        let monday = days_from_civil(2026, 11, 2);
        let tallies = [
            // Today: three copies, one of them new, and both others' first this week.
            tally(today, true, true, true, 1),
            tally(today, false, true, false, 2),
            // Monday: four copies, all first this week and this month.
            tally(monday, false, true, true, 4),
            // Last week, in October: two.
            tally(monday - 3, false, true, true, 2),
        ];
        let report = numbers(&tallies, today).text();
        let line = |start: &str| {
            report
                .lines()
                .find(|line| line.trim_start().starts_with(start))
                .unwrap_or_else(|| panic!("no line for {start} in\n{report}"))
                .split_whitespace()
                .skip(1)
                .collect::<Vec<_>>()
        };
        assert_eq!(line("2026-11-06"), ["3", "1"]);
        assert_eq!(line("2026-11-02"), ["4", "0"]);
        assert_eq!(line("2026-11-05"), ["0", "0"]);
        assert_eq!(line("2026-W45"), ["7"]);
        assert_eq!(line("2026-W44"), ["2"]);
        assert_eq!(line("2026-11 "), ["5"]);
        assert_eq!(line("2026-10 "), ["2"]);
        // 14 days, 8 weeks, 6 months and three headings.
        assert_eq!(report.lines().count(), 14 + 8 + 6 + 3);
    }

    #[test]
    fn each_day_is_broken_down_by_kind_of_copy() {
        let today = days_from_civil(2026, 11, 9);
        let kind = |os: &str, version: &str| Kind {
            os: os.into(),
            os_major: 6,
            chip: "x64".into(),
            version: version.into(),
            channel: "release".into(),
        };
        let row = |day, kind: Kind, first, count| Tally {
            kind,
            ..tally(day, first, false, false, count)
        };
        let tallies = [
            row(today, kind("linux", "0.1.12"), true, 9),
            row(today, kind("linux", "0.1.12"), false, 2),
            row(today, kind("macos", "0.1.13"), false, 3),
            row(today - 1, kind("macos", "0.1.13"), true, 1),
            // Before the 14 days: in no day's breakdown.
            row(today - 14, kind("windows", "0.1.9"), false, 5),
        ];
        let numbers = numbers(&tallies, today);
        assert_eq!(numbers.kinds.len(), numbers.days.len());
        // A kind's rows add up, the most users first, and a day's kinds add up to its users.
        assert_eq!(
            numbers.kinds[0],
            [
                (kind("linux", "0.1.12"), 11, 9),
                (kind("macos", "0.1.13"), 3, 0)
            ]
        );
        assert_eq!(numbers.days[0].1, 14);
        assert_eq!(numbers.kinds[1], [(kind("macos", "0.1.13"), 1, 1)]);
        assert!(numbers.kinds[2..].iter().all(Vec::is_empty));
    }

    #[test]
    fn only_what_ilo_sends_is_a_count() {
        let count = |version: &str, os: &str, daily: bool| Count {
            version: version.into(),
            channel: "release".into(),
            os: os.into(),
            os_major: 15,
            chip: "arm64".into(),
            first: false,
            daily,
            weekly: false,
            monthly: false,
        };
        assert!(count("0.1.9", "macos", true).valid());
        assert!(!count("0.1.9", "macos", false).valid());
        assert!(!count("0.1.9", "plan9", true).valid());
        for version in ["", "1..2", "0.1.9-dev", "1.2.3.4.5.6.7.8.9", "v1"] {
            assert!(!count(version, "linux", true).valid(), "{version}");
        }
    }
}
