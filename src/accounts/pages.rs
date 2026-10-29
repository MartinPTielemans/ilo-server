//! The sign-in pages ilo shows in a tab. Plain HTML from the server, one
//! stylesheet, and one small script for passkeys.

use axum::http::header;
use axum::response::{Html, IntoResponse, Response};

/// Nothing inline: the stylesheet and the script come from the server itself,
/// forms post only to it, and no other site can frame the pages.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// ilo's mark, the dot and the stem from its icon (the browser's
/// `app/branding/ilo.icon`), with the stem in the page's ink.
const MARK: &str = r##"<svg class="mark" viewBox="419.8 184.3 184.4 624.7" role="img" aria-label="ilo"><circle cx="512" cy="276.5" r="92.2" fill="#0E9F55"/><rect x="445.4" y="450.6" width="133.1" height="358.4" rx="66.6" fill="currentColor"/></svg>"##;

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(title: &str, head: &str, body: &str) -> Response {
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
{head}<title>{title} · ilo</title>
<link rel="stylesheet" href="/sign-in.css">
<script src="/sign-in.js" defer></script>
</head>
<body>
<main>
{MARK}
<h1>{title}</h1>
{body}
</main>
</body>
</html>
"#
    );
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Html(html),
    )
        .into_response()
}

fn alert(error: Option<&str>) -> String {
    error
        .map(|error| format!(r#"<p class="error" role="alert">{}</p>"#, escape(error)))
        .unwrap_or_default()
}

pub fn email(hint: Option<&str>, error: Option<&str>) -> Response {
    page(
        "Sign in to ilo",
        "",
        &format!(
            r#"<p>Sync your browser between your devices. Enter your email, and we'll send you a code.</p>
{}
<form method="post" action="/authorize/email">
<input name="email" type="email" autocomplete="email webauthn" required autofocus placeholder="you@example.com" value="{}" aria-label="Email">
<button>Continue</button>
</form>"#,
            alert(error),
            escape(hint.unwrap_or_default())
        ),
    )
}

/// The account has a passkey, so it's the first way offered.
pub fn choose(email: &str, error: Option<&str>) -> Response {
    page(
        "Sign in to ilo",
        "",
        &format!(
            r#"<p>Signing in as <strong>{}</strong>.</p>
{}<p class="error" id="passkey-error" role="alert" hidden></p>
<form><button type="button" data-passkey="login" autofocus>Use your passkey</button></form>
<form method="post" action="/authorize/send-code"><button class="quiet">Email me a code instead</button></form>"#,
            escape(email),
            alert(error)
        ),
    )
}

pub struct Code<'a> {
    pub email: &'a str,
    /// Until the code expires, rounded up: 0 once it has.
    pub minutes: i64,
    /// Whether the one new code a sign-in may ask for is still unsent.
    pub resend: bool,
    /// Said once a new code is sent.
    pub note: Option<&'a str>,
    pub error: Option<&'a str>,
}

pub fn code(sent: Code) -> Response {
    let expires = match sent.minutes {
        ..=0 => "It has expired.".to_owned(),
        1 => "It expires in 1 minute.".to_owned(),
        minutes => format!("It expires in {minutes} minutes."),
    };
    let note = sent
        .note
        .map(|note| format!(r#"<p class="note" role="status">{}</p>"#, escape(note)))
        .unwrap_or_default();
    let resend = if sent.resend {
        r#"<form method="post" action="/authorize/send-code"><button class="link">Send a new code</button></form>"#
    } else {
        ""
    };
    page(
        "Check your email",
        "",
        &format!(
            r#"<p>We sent a 6-digit code to <strong>{}</strong>. {expires}</p>
{note}{}
<form method="post" action="/authorize/code">
<input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" maxlength="12" required autofocus placeholder="000000" aria-label="Code">
<button>Sign in</button>
</form>
{resend}"#,
            escape(sent.email),
            alert(sent.error)
        ),
    )
}

pub fn add_passkey() -> Response {
    page(
        "Add a passkey",
        "",
        r#"<p>Next time, sign in with your fingerprint, face or device PIN instead of a code.</p>
<p class="error" id="passkey-error" role="alert" hidden></p>
<form><button type="button" data-passkey="register" autofocus>Add a passkey</button></form>
<form method="post" action="/authorize/continue"><button class="quiet">Not now</button></form>"#,
    )
}

/// Shown for a moment before the tab goes back to the app with its code.
pub fn done(email: &str, url: &str) -> Response {
    let url = escape(url);
    page(
        "You're signed in",
        &format!("<meta http-equiv=\"refresh\" content=\"1; url={url}\">\n"),
        &format!(
            r#"<p>Signed in as <strong>{}</strong>. Taking you back to ilo.</p>
<div class="actions"><a class="button" href="{url}">Return to ilo</a></div>"#,
            escape(email)
        ),
    )
}

pub fn failure(message: &str) -> Response {
    page(
        "Can't sign in",
        "",
        &format!(
            r#"<p role="alert">{}</p>
<p>Start again from ilo.</p>"#,
            escape(message)
        ),
    )
}

pub fn signed_in() -> Response {
    page("You're signed in", "", "<p>You can close this tab.</p>")
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-cache"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

pub async fn script() -> Response {
    asset("text/javascript; charset=utf-8", include_str!("sign-in.js"))
}

pub async fn style() -> Response {
    asset("text/css; charset=utf-8", include_str!("sign-in.css"))
}
