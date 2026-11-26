//! The sign-in pages ilo shows in a tab. Plain HTML from the server, one
//! stylesheet, and one small script for passkeys.

use axum::http::header;
use axum::response::{Html, IntoResponse, Response};

/// Nothing inline: the stylesheet and the script come from the server itself,
/// forms post only to it, and no other site can frame the pages.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// ilo's wordmark, a dot, two stems and a ring, with the dot in Signal green and the rest in
/// the page's ink. The code mail shows it as PNGs drawn from this (src/mail).
const MARK: &str = r##"<svg class="mark" viewBox="4 16 217 154" role="img" aria-label="ilo"><circle cx="19" cy="31" r="15" fill="#0E9F55"/><rect x="7" y="70" width="24" height="100" rx="12" fill="currentColor"/><rect x="67" y="20" width="24" height="150" rx="12" fill="currentColor"/><circle cx="171" cy="120" r="38" fill="none" stroke="currentColor" stroke-width="24"/></svg>"##;

/// Google's "G", in Google's colours, as Google's sign-in branding asks the button to carry it.
const GOOGLE_G: &str = r##"<svg viewBox="0 0 48 48" aria-hidden="true"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>"##;

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

/// The first page. `google` draws Google's button, for a server with a Google client.
pub fn email(hint: Option<&str>, error: Option<&str>, google: bool) -> Response {
    // A link, not a form: `form-action 'self'` would stop a form's redirect on to Google.
    let google = if google {
        format!(
            r#"<div class="actions"><a class="button quiet google" href="/authorize/google/start">{GOOGLE_G}Continue with Google</a></div>
"#
        )
    } else {
        String::new()
    };
    page(
        "Sign in to ilo",
        "",
        &format!(
            r#"<p>Sync your browser between your devices. Enter your email, and we'll send you a code.</p>
{}
<form method="post" action="/authorize/email">
<input name="email" type="email" autocomplete="email webauthn" required autofocus placeholder="you@example.com" value="{}" aria-label="Email">
<button>Continue</button>
</form>
<p class="error" id="passkey-error" role="alert" hidden></p>
{google}<form><button type="button" class="quiet" data-passkey="login">Use a passkey</button></form>"#,
            alert(error),
            escape(hint.unwrap_or_default())
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
    /// Whether the code links a Google account to the address.
    pub linking: bool,
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
            r#"<p>{} <strong>{}</strong>. {expires}</p>
{note}{}
<form method="post" action="/authorize/code">
<input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" maxlength="12" required autofocus placeholder="000000" aria-label="Code">
<button>Sign in</button>
</form>
{resend}"#,
            if sent.linking {
                "To use Google sign-in, enter the 6-digit code we sent to"
            } else {
                "We sent a 6-digit code to"
            },
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
