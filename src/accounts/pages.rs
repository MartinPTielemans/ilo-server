//! The sign-in pages ilo shows in a tab. Plain HTML, one small script for passkeys.

use axum::http::header;
use axum::response::{Html, IntoResponse, Response};

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(title: &str, body: &str) -> Response {
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · ilo</title>
<style>
:root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; }}
main {{ width: min(22rem, 100% - 2rem); }}
h1 {{ font-size: 1.4rem; margin: 0 0 .5rem; }}
p {{ line-height: 1.45; }}
form {{ display: grid; gap: .6rem; margin: 1rem 0 0; }}
input, button {{ font: inherit; padding: .6rem .7rem; border-radius: .5rem; }}
input {{ border: 1px solid #8886; }}
button {{ border: 0; background: #3d5afe; color: white; cursor: pointer; }}
button.quiet {{ background: none; color: inherit; text-decoration: underline; padding: 0; justify-self: start; }}
.error {{ color: #d32f2f; }}
</style>
<script src="/sign-in.js" defer></script>
</head>
<body><main>
<h1>{title}</h1>
{body}
</main></body>
</html>"#
    );
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; \
                 connect-src 'self'; frame-ancestors 'none'",
            ),
        ],
        Html(html),
    )
        .into_response()
}

fn error_line(error: Option<&str>) -> String {
    error
        .map(|error| format!(r#"<p class="error" role="alert">{}</p>"#, escape(error)))
        .unwrap_or_default()
}

pub fn email(hint: Option<&str>, error: Option<&str>) -> Response {
    page(
        "Sign in to ilo",
        &format!(
            r#"<p>Sync your browser between your devices. Enter your email, and we'll send you a code.</p>
{}
<form method="post" action="/authorize/email">
<input name="email" type="email" autocomplete="email webauthn" required autofocus placeholder="you@example.com" value="{}" aria-label="Email">
<button>Continue</button>
</form>"#,
            error_line(error),
            escape(hint.unwrap_or_default())
        ),
    )
}

pub fn choose(email: &str) -> Response {
    page(
        "Sign in to ilo",
        &format!(
            r#"<p>Signing in as {}.</p>
<p class="error" id="passkey-error" role="alert" hidden></p>
<form><button type="button" data-passkey="login" autofocus>Use your passkey</button></form>
<form method="post" action="/authorize/send-code"><button class="quiet">Email me a code instead</button></form>"#,
            escape(email)
        ),
    )
}

pub fn code(email: &str, error: Option<&str>) -> Response {
    page(
        "Check your email",
        &format!(
            r#"<p>We sent a code to {}. It works for 10 minutes.</p>
{}
<form method="post" action="/authorize/code">
<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" required autofocus aria-label="Code">
<button>Sign in</button>
</form>
<form method="post" action="/authorize/send-code"><button class="quiet">Send a new code</button></form>"#,
            escape(email),
            error_line(error)
        ),
    )
}

pub fn add_passkey() -> Response {
    page(
        "Add a passkey",
        r#"<p>Next time, sign in with your fingerprint, face or device PIN instead of a code.</p>
<p class="error" id="passkey-error" role="alert" hidden></p>
<form><button type="button" data-passkey="register" autofocus>Add a passkey</button></form>
<form method="post" action="/authorize/continue"><button class="quiet">Not now</button></form>"#,
    )
}

pub fn failure(message: &str) -> Response {
    page(
        "Can't sign in",
        &format!("<p>{}</p><p>Start again from ilo.</p>", escape(message)),
    )
}

pub fn signed_in() -> Response {
    page("You're signed in", "<p>You can close this tab.</p>")
}

pub async fn script() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        include_str!("sign-in.js"),
    )
        .into_response()
}
