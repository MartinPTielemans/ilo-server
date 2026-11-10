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
    // The report reads them back, on Postgres too, where other tests' counts add to today's.
    let numbers = ilo_server::counts::read(&server.db, today).await.unwrap();
    assert!(
        numbers.days[0].1 >= 3 && numbers.days[0].2 >= 1,
        "{numbers:?}"
    );
}

#[tokio::test]
async fn the_table_keeps_no_address_agent_or_time_of_day() {
    let server = common::start().await;
    let columns: Vec<String> = match std::env::var("ILO_TEST_DATABASE_URL") {
        Ok(_) => sqlx::query(
            "SELECT column_name::text AS column_name FROM information_schema.columns \
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

async fn counts_page(
    server: &common::Server,
    credentials: Option<(&str, &str)>,
) -> reqwest::Response {
    let request = reqwest::Client::new().get(format!("{}/counts", server.url));
    let request = match credentials {
        Some((user, password)) => request.basic_auth(user, Some(password)),
        None => request,
    };
    request.send().await.unwrap()
}

#[tokio::test]
async fn without_a_password_there_is_no_counts_page() {
    let server = common::start().await;
    let page = counts_page(&server, None).await;
    assert_eq!(page.status(), reqwest::StatusCode::NOT_FOUND);
    let page = counts_page(&server, Some(("ilo", ""))).await;
    assert_eq!(page.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_counts_page_asks_for_the_password() {
    let server = common::start_alone(&[("COUNTS_PASSWORD", "a-long-test-password")]).await;
    for credentials in [
        None,
        Some(("ilo", "wrong")),
        Some(("admin", "a-long-test-password")),
    ] {
        let page = counts_page(&server, credentials).await;
        assert_eq!(
            page.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{credentials:?}"
        );
        let asks = page.headers()["www-authenticate"].to_str().unwrap();
        assert!(asks.starts_with("Basic "), "{asks}");
        assert_eq!(page.headers()["cache-control"], "no-store");
        assert!(!page.text().await.unwrap().contains("users"));
    }
}

#[tokio::test]
async fn the_counts_page_shows_what_the_command_prints() {
    let server = common::start_alone(&[("COUNTS_PASSWORD", "a-long-test-password")]).await;
    let version = unique_version();
    for body in [
        count(&version, true, true, true),
        count(&version, false, true, false),
        count(&version, false, false, false),
    ] {
        assert_eq!(post(&server, &body).await, reqwest::StatusCode::NO_CONTENT);
    }
    let page = counts_page(&server, Some(("ilo", "a-long-test-password"))).await;
    assert_eq!(page.status(), reqwest::StatusCode::OK);
    let headers = page.headers().clone();
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["x-robots-tag"], "noindex");
    assert!(
        headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .starts_with("default-src 'none'")
    );
    let html = page.text().await.unwrap();
    // Nothing from anywhere else, and no script.
    assert!(!html.contains("<script"));
    assert!(!html.contains("src="));
    assert!(!html.contains("href="));
    assert!(html.contains("prefers-color-scheme: dark"));
    assert!(html.contains("<svg"));

    // The same numbers as `ilo-server counts`, from the same query, row by row.
    let numbers = ilo_server::counts::read(&server.db, ilo_server::counts::today())
        .await
        .unwrap();
    let today = &numbers.days[0];
    assert_eq!((today.1, today.2), (3, 1));
    assert_eq!(numbers.weeks[0].1, 2);
    assert_eq!(numbers.months[0].1, 1);
    for (day, users, new) in &numbers.days {
        let row = format!("<th scope=\"row\">{day}</th><td>{users}</td><td>{new}</td>");
        assert!(html.contains(&row), "no {row} in the page");
    }
    for (label, users) in numbers.weeks.iter().chain(&numbers.months) {
        let row = format!("<th scope=\"row\">{label}</th><td>{users}</td>");
        assert!(html.contains(&row), "no {row} in the page");
    }
    // Today broken down by kind: this test's copies are one, macOS 26 on arm64. On a shared
    // Postgres other tests' copies are other versions, so they're rows of their own.
    let row = format!(
        "<tr><th scope=\"row\">macOS 26</th><td>arm64</td><td>{version}</td><td>release</td>\
         <td class=\"n\">3</td><td class=\"n\">1</td></tr>"
    );
    assert!(html.contains(&row), "no {row} in the page");

    // And each of the command's lines has its row, so the two can't show different days.
    let text = numbers.text();
    let lines: Vec<&str> = text.lines().filter(|line| line.starts_with("  ")).collect();
    assert_eq!(lines.len(), 14 + 8 + 6);
    for line in lines {
        let mut words = line.split_whitespace();
        let label = words.next().unwrap();
        let cells: String = words.map(|word| format!("<td>{word}</td>")).collect();
        let row = format!("<th scope=\"row\">{label}</th>{cells}");
        assert!(
            html.contains(&row),
            "the command's {line:?} isn't in the page"
        );
    }
}
