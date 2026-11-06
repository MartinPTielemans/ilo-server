//! The daily usage count, posted as ilo's core posts it.

mod common;

use serde_json::{Value, json};
use sqlx::Row as _;

/// A version no other test sends, so tests sharing a Postgres count only their own.
fn unique_version() -> String {
    let [a, b, c, d] = ilo_server::db::random_bytes::<4>();
    format!("{}.{}.{}", u16::from(a) * 100 + u16::from(b) % 100, c, d)
}

fn count(version: &str, first: bool, weekly: bool, monthly: bool) -> Value {
    json!({
        "version": version,
        "channel": "release",
        "os": "macos",
        "os_major": 26,
        "chip": "arm64",
        "first": first,
        "daily": true,
        "weekly": weekly,
        "monthly": monthly,
    })
}

async fn post(server: &common::Server, body: &Value) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!("{}/v1/daily", server.url))
        .header("user-agent", "ilo-check")
        .json(body)
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn counts_are_kept_as_numbers_per_day_and_fields() {
    let server = common::start().await;
    let version = unique_version();
    for body in [
        count(&version, true, true, true),
        count(&version, false, true, false),
        count(&version, false, true, false),
    ] {
        assert_eq!(post(&server, &body).await, reqwest::StatusCode::NO_CONTENT);
    }
    let rows = sqlx::query(
        "SELECT day, first_run, weekly, monthly, count FROM daily_counts WHERE version = $1 \
         ORDER BY first_run",
    )
    .bind(&version)
    .fetch_all(&server.db)
    .await
    .unwrap();
    let rows: Vec<(i64, i64, i64, i64, i64)> = rows
        .iter()
        .map(|row| {
            (
                row.get("day"),
                row.get("first_run"),
                row.get("weekly"),
                row.get("monthly"),
                row.get("count"),
            )
        })
        .collect();
    let today = ilo_server::counts::today();
    // Two rows, one a count of two: nothing tells the copies apart.
    assert_eq!(rows, [(today, 0, 1, 0, 2), (today, 1, 1, 1, 1)]);
}

#[tokio::test]
async fn the_table_keeps_no_address_agent_or_time_of_day() {
    let server = common::start().await;
    let columns: Vec<String> = match std::env::var("ILO_TEST_DATABASE_URL") {
        Ok(_) => sqlx::query(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_name = 'daily_counts' ORDER BY ordinal_position",
        )
        .fetch_all(&server.db)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<String, _>("column_name"))
        .collect(),
        Err(_) => sqlx::query("SELECT name FROM pragma_table_info('daily_counts')")
            .fetch_all(&server.db)
            .await
            .unwrap()
            .iter()
            .map(|row| row.get::<String, _>("name"))
            .collect(),
    };
    assert_eq!(
        columns,
        [
            "day",
            "version",
            "channel",
            "os",
            "os_major",
            "chip",
            "first_run",
            "weekly",
            "monthly",
            "count"
        ]
    );
}

#[tokio::test]
async fn anything_ilo_doesnt_send_is_refused() {
    let server = common::start().await;
    let version = unique_version();
    let mut not_daily = count(&version, false, false, false);
    not_daily["daily"] = json!(false);
    let mut other_os = count(&version, false, false, false);
    other_os["os"] = json!("plan9");
    let mut missing = count(&version, false, false, false);
    missing.as_object_mut().unwrap().remove("chip");
    let mut long_version = count(&version, false, false, false);
    long_version["version"] = json!("1.2.3-a-much-longer-string");
    for body in [not_daily, other_os, missing, long_version] {
        let status = post(&server, &body).await;
        assert!(status.is_client_error(), "{body} was answered {status}");
    }
    let stored: i64 = sqlx::query("SELECT COUNT(*) AS n FROM daily_counts WHERE version = $1")
        .bind(&version)
        .fetch_one(&server.db)
        .await
        .unwrap()
        .get("n");
    assert_eq!(stored, 0);
    // A field ilo doesn't send is dropped, not stored.
    let mut extra = count(&version, false, false, false);
    extra["id"] = json!("abc");
    assert_eq!(post(&server, &extra).await, reqwest::StatusCode::NO_CONTENT);
}
