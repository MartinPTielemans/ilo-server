//! `GET /counts`: the daily usage count's numbers as a page, for whoever has `COUNTS_PASSWORD`,
//! the same numbers `ilo-server counts` prints (`counts::read`). It asks for HTTP Basic auth, as
//! user `ilo`, rather than a token in the URL, which Railway's edge logs record with each path.
//! Without the password set the route answers 404, as a path the server doesn't have does, so a
//! self-hosted server has no page unless its owner sets one.
//!
//! The page is plain HTML with its style and its one chart inline: no script, and nothing loaded
//! from anywhere, which its Content-Security-Policy holds it to.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::Shared;
use crate::counts::{self, Numbers};

/// The user Basic auth asks for.
pub const USER: &str = "ilo";

pub async fn page(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let Some(password) = &state.config.counts_password else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !authorized(&headers, &password.0) {
        let mut response = private(StatusCode::UNAUTHORIZED.into_response());
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"ilo counts\", charset=\"UTF-8\""),
        );
        return response;
    }
    match counts::read(&state.db, counts::today()).await {
        Ok(numbers) => {
            let mut response = private(html(&numbers).into_response());
            response.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(
                    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; \
                     form-action 'none'; frame-ancestors 'none'",
                ),
            );
            response
        }
        Err(error) => {
            tracing::error!(%error, "the counts weren't read");
            private(StatusCode::SERVICE_UNAVAILABLE.into_response())
        }
    }
}

/// Neither kept by a cache nor indexed by a search engine.
fn private(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    response
}

/// Whether the request's Basic credentials are `ilo` and `password`. Both sides are hashed first,
/// so the comparison takes the same time whatever was sent and wherever it differs.
fn authorized(headers: &HeaderMap, password: &str) -> bool {
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .and_then(|(_, credentials)| STANDARD.decode(credentials.trim()).ok())
        .unwrap_or_default();
    let expected = format!("{USER}:{password}");
    openssl::memcmp::eq(
        &openssl::sha::sha256(&given),
        &openssl::sha::sha256(expected.as_bytes()),
    )
}

/// The page, from the numbers alone: every value in it is a date or a number the server made, or a
/// field of a count, which the endpoint took only from the values ilo sends and the page escapes
/// all the same.
pub fn html(numbers: &Numbers) -> axum::response::Html<String> {
    let today = numbers.days.first().map_or(0, |(_, users, _)| *users);
    let week = numbers.weeks.first().map_or(0, |(_, users)| *users);
    let month = numbers.months.first().map_or(0, |(_, users)| *users);
    let mut days = String::new();
    for (day, users, new) in &numbers.days {
        days += &format!("<tr><th scope=\"row\">{day}</th><td>{users}</td><td>{new}</td></tr>\n");
    }
    let rows = |list: &[(String, i64)]| {
        list.iter()
            .map(|(label, users)| {
                format!("<tr><th scope=\"row\">{label}</th><td>{users}</td></tr>\n")
            })
            .collect::<String>()
    };
    let (weeks, months) = (rows(&numbers.weeks), rows(&numbers.months));
    let kinds = kinds(numbers);
    let chart = chart(numbers);
    axum::response::Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>ilo counts</title>
<style>
:root {{
  color-scheme: light dark;
  --ground: #faf9f7; --ink: #1d1c1a; --muted: #6c6862; --line: #e5e1db; --bar: #3d6fa3;
}}
@media (prefers-color-scheme: dark) {{
  :root {{ --ground: #151413; --ink: #ece9e4; --muted: #9b968e; --line: #2d2b28; --bar: #7ea9d8; }}
}}
body {{
  margin: 0; background: var(--ground); color: var(--ink);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
}}
main {{ max-width: 40rem; margin: 0 auto; padding: 24px 16px 48px; }}
h1 {{ font-size: 1.375rem; margin: 0 0 4px; }}
h2 {{ font-size: 1rem; margin: 32px 0 8px; }}
p {{ margin: 0; color: var(--muted); font-size: 0.875rem; }}
.totals {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin: 24px 0 0; }}
.totals div {{ border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }}
.totals dt {{ color: var(--muted); font-size: 0.8125rem; }}
.totals dd {{ margin: 0; font-size: 1.5rem; font-variant-numeric: tabular-nums; }}
svg {{ display: block; width: 100%; height: auto; margin: 8px 0 16px; }}
svg .bar {{ fill: var(--bar); }}
svg .base {{ stroke: var(--line); }}
svg text {{ fill: var(--muted); font-size: 9px; font-family: inherit; }}
table {{ width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }}
th, td {{ padding: 6px 0; border-bottom: 1px solid var(--line); text-align: right; }}
th[scope="row"] {{ text-align: left; font-weight: normal; }}
thead th {{ color: var(--muted); font-weight: 500; font-size: 0.8125rem; }}
thead th:first-child {{ text-align: left; }}
.kinds td, .kinds thead th {{ text-align: left; }}
.kinds .n, .kinds thead .n {{ text-align: right; }}
details {{ border-bottom: 1px solid var(--line); }}
summary {{ padding: 6px 0; cursor: pointer; font-variant-numeric: tabular-nums; }}
summary span {{ color: var(--muted); }}
details table {{ margin: 0 0 12px; }}
details tr:last-child > * {{ border-bottom: 0; }}
</style>
</head>
<body>
<main>
<h1>ilo counts</h1>
<p>Copies of ilo that sent their daily count, by UTC day. The current week and month are still filling.</p>
<dl class="totals">
<div><dt>Today</dt><dd>{today}</dd></div>
<div><dt>This week</dt><dd>{week}</dd></div>
<div><dt>This month</dt><dd>{month}</dd></div>
</dl>
<h2>Daily users, last 14 days</h2>
{chart}
<table>
<thead><tr><th scope="col">Day (UTC)</th><th scope="col">Users</th><th scope="col">New</th></tr></thead>
<tbody>
{days}</tbody>
</table>
<h2>Each day by system, chip, version and channel</h2>
{kinds}<h2>Weekly users</h2>
<table>
<thead><tr><th scope="col">ISO week</th><th scope="col">Users</th></tr></thead>
<tbody>
{weeks}</tbody>
</table>
<h2>Monthly users</h2>
<table>
<thead><tr><th scope="col">Month</th><th scope="col">Users</th></tr></thead>
<tbody>
{months}</tbody>
</table>
</main>
</body>
</html>
"#
    ))
}

/// Each of the 14 days that had counts, newest first and open, as the kinds of copy that counted
/// on it, so a day's users can be told apart: a release's, a nightly's, one system's.
fn kinds(numbers: &Numbers) -> String {
    let mut out = String::new();
    let days = numbers.days.iter().zip(&numbers.kinds);
    for ((day, users, new), kinds) in days.filter(|(_, kinds)| !kinds.is_empty()) {
        let open = if out.is_empty() { " open" } else { "" };
        let people = if *users == 1 { "user" } else { "users" };
        out += &format!(
            "<details{open}><summary>{day} <span>{users} {people}, {new} new</span></summary>\n\
             <table class=\"kinds\">\n<thead><tr><th scope=\"col\">System</th>\
             <th scope=\"col\">Chip</th><th scope=\"col\">Version</th>\
             <th scope=\"col\">Channel</th><th scope=\"col\" class=\"n\">Users</th>\
             <th scope=\"col\" class=\"n\">New</th></tr></thead>\n<tbody>\n"
        );
        for (kind, users, new) in kinds {
            let system = match kind.os.as_str() {
                "macos" => "macOS",
                "windows" => "Windows",
                "linux" => "Linux",
                other => other,
            };
            out += &format!(
                "<tr><th scope=\"row\">{} {}</th><td>{}</td><td>{}</td><td>{}</td>\
                 <td class=\"n\">{users}</td><td class=\"n\">{new}</td></tr>\n",
                escape(system),
                kind.os_major,
                escape(&kind.chip),
                escape(&kind.version),
                escape(&kind.channel),
            );
        }
        out += "</tbody>\n</table>\n</details>\n";
    }
    if out.is_empty() {
        out = "<p>No counts in the last 14 days.</p>\n".into();
    }
    out
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A bar a day for the last 14, oldest on the left, each with its number as its title.
fn chart(numbers: &Numbers) -> String {
    const WIDTH: i64 = 280;
    const TOP: i64 = 8;
    const HEIGHT: i64 = 96;
    let pitch = WIDTH / 14;
    let most = (numbers.days.iter())
        .map(|(_, users, _)| *users)
        .max()
        .unwrap_or(0)
        .max(1);
    let mut bars = String::new();
    for (place, (day, users, _)) in numbers.days.iter().rev().enumerate() {
        let x = place as i64 * pitch + 3;
        let height = users * HEIGHT / most;
        let y = TOP + HEIGHT - height;
        let date = day
            .rsplit('-')
            .next()
            .unwrap_or(day)
            .trim_start_matches('0');
        bars += &format!(
            "<rect class=\"bar\" x=\"{x}\" y=\"{y}\" width=\"{}\" height=\"{height}\" rx=\"2\">\
             <title>{day}: {users}</title></rect>\
             <text x=\"{}\" y=\"{}\" text-anchor=\"middle\">{date}</text>\n",
            pitch - 6,
            x + (pitch - 6) / 2,
            TOP + HEIGHT + 12,
        );
    }
    format!(
        "<svg viewBox=\"0 0 {WIDTH} {}\" role=\"img\" aria-label=\"Daily users, last 14 days, \
         most {most}\">\n<line class=\"base\" x1=\"0\" x2=\"{WIDTH}\" y1=\"{base}\" y2=\"{base}\"/>\n\
         {bars}</svg>",
        TOP + HEIGHT + 16,
        base = TOP + HEIGHT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(credentials: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let value = format!("Basic {}", STANDARD.encode(credentials));
        headers.insert(header::AUTHORIZATION, value.parse().unwrap());
        headers
    }

    #[test]
    fn only_ilo_and_the_password_are_let_in() {
        assert!(authorized(&basic("ilo:right"), "right"));
        assert!(!authorized(&basic("ilo:wrong"), "right"));
        assert!(!authorized(&basic("ilo:righ"), "right"));
        assert!(!authorized(&basic("admin:right"), "right"));
        assert!(!authorized(&basic("ilo:"), "right"));
        assert!(!authorized(&HeaderMap::new(), "right"));
        let mut bearer = HeaderMap::new();
        bearer.insert(header::AUTHORIZATION, "Bearer right".parse().unwrap());
        assert!(!authorized(&bearer, "right"));
        // A password with a colon is the rest of the credentials.
        assert!(authorized(&basic("ilo:a:b"), "a:b"));
    }

    #[test]
    fn a_day_is_broken_down_by_kind_and_a_day_without_counts_is_left_out() {
        let mut numbers = counts::numbers(&[], 20_766);
        assert!(kinds(&numbers).contains("No counts in the last 14 days."));
        let kind = |os: &str, version: &str| counts::Kind {
            os: os.into(),
            os_major: 6,
            chip: "x64".into(),
            version: version.into(),
            channel: "release".into(),
        };
        numbers.kinds[0] = vec![(kind("linux", "0.1.12"), 11, 11)];
        numbers.kinds[2] = vec![(kind("<b>", "0.1.13"), 1, 0)];
        let html = kinds(&numbers);
        assert_eq!(html.matches("<details").count(), 2);
        assert_eq!(html.matches("<details open>").count(), 1);
        assert!(html.contains(
            "<tr><th scope=\"row\">Linux 6</th><td>x64</td><td>0.1.12</td><td>release</td>\
             <td class=\"n\">11</td><td class=\"n\">11</td></tr>"
        ));
        assert!(html.contains("&lt;b&gt; 6"));
        assert!(!html.contains("<b>"));
    }

    #[test]
    fn the_chart_has_a_bar_a_day_scaled_to_the_most() {
        let mut numbers = counts::numbers(&[], 20_763);
        numbers.days[0].1 = 10;
        numbers.days[13].1 = 5;
        let chart = chart(&numbers);
        assert_eq!(chart.matches("<rect").count(), 14);
        // The newest, on the right, is the whole height; the oldest, on the left, half of it.
        assert!(chart.contains("height=\"96\" rx=\"2\"><title>2026-11-06: 10</title>"));
        assert!(chart.contains("height=\"48\" rx=\"2\"><title>2026-10-24: 5</title>"));
        assert!(!chart.contains("http"));
    }
}
