//! `/authorize`: the pages between ilo opening a sign-in tab and the redirect
//! that hands it an authorization code.
//!
//! A cookie names the sign-in, so its pages work only in the browser that
//! started it.

use axum::Json;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::json;
use url::Url;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Uuid,
};

use super::pages;
use crate::Shared;
use crate::config::Config;
use crate::db::{self, Db};

pub const CLIENT_ID: &str = "ilo";
const COOKIE: &str = "ilo_sign_in";
const SIGN_IN_LIFETIME: i64 = 15 * 60;
const CODE_LIFETIME: i64 = 10 * 60;
const CODE_RESEND_AFTER: i64 = 30;
const CODE_ATTEMPTS: i64 = 5;
/// The first code and one new one.
const CODES_PER_SIGN_IN: i64 = 2;
/// Codes an address gets in an hour, across every sign-in that asks: five tries
/// each, so guessing one of a million codes takes years, not hours.
const CODES_PER_ADDRESS_PER_HOUR: i64 = 5;
const HOUR: i64 = 60 * 60;
const DAY: i64 = 24 * HOUR;
pub const AUTHORIZATION_CODE_LIFETIME: i64 = 60;

#[derive(Deserialize)]
pub struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    login_hint: Option<String>,
}

#[derive(sqlx::FromRow)]
struct SignIn {
    id: String,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: String,
    scope: String,
    email: Option<String>,
    account_id: Option<String>,
    ceremony: Option<String>,
    codes_sent: i64,
    finished_url: Option<String>,
}

/// Loopback addresses (RFC 8252), the server's own `/signed-in` page, which
/// ilo can watch its tab arrive at, and whatever the server's operator adds.
pub fn allowed_redirect(config: &Config, uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    if url.fragment().is_some() {
        return false;
    }
    let loopback = url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    let own = url.origin() == config.public_url.origin() && url.path() == "/signed-in";
    loopback || own || config.redirect_uris.iter().any(|allowed| allowed == uri)
}

fn redirect_with(redirect_uri: &str, params: &[(&str, &str)]) -> String {
    let mut url = Url::parse(redirect_uri).expect("redirect URIs are checked before use");
    url.query_pairs_mut().extend_pairs(params);
    url.into()
}

fn cookie(config: &Config, value: &str, max_age: i64) -> String {
    let secure = if config.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    format!("{COOKIE}={value}; Path=/authorize; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}")
}

fn internal(error: anyhow::Error) -> Response {
    tracing::error!(%error, "sign-in failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        pages::failure("Something went wrong on the server."),
    )
        .into_response()
}

pub async fn authorize(
    State(state): State<Shared>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    if params.client_id.as_deref() != Some(CLIENT_ID) {
        return (
            StatusCode::BAD_REQUEST,
            pages::failure("This app isn't one the server knows."),
        )
            .into_response();
    }
    let Some(redirect_uri) = params
        .redirect_uri
        .filter(|uri| allowed_redirect(&state.config, uri))
    else {
        return (
            StatusCode::BAD_REQUEST,
            pages::failure("The app asked to return to an address the server doesn't allow."),
        )
            .into_response();
    };
    let reply_error = |error: &str, description: &str| {
        let mut reply = vec![("error", error), ("error_description", description)];
        if let Some(sent) = params.state.as_deref() {
            reply.push(("state", sent));
        }
        let issuer = state.config.issuer();
        reply.push(("iss", &issuer));
        Redirect::to(&redirect_with(&redirect_uri, &reply)).into_response()
    };
    if params.response_type.as_deref() != Some("code") {
        return reply_error(
            "unsupported_response_type",
            "only the code flow is supported",
        );
    }
    let Some(code_challenge) = params
        .code_challenge
        .filter(|_| params.code_challenge_method.as_deref() == Some("S256"))
    else {
        return reply_error("invalid_request", "PKCE with S256 is required");
    };
    match start(
        &state.db,
        &redirect_uri,
        params.state,
        params.nonce,
        code_challenge,
        params.scope,
    )
    .await
    {
        Ok(id) => (
            [(
                header::SET_COOKIE,
                cookie(&state.config, &id, SIGN_IN_LIFETIME),
            )],
            pages::email(params.login_hint.as_deref(), None),
        )
            .into_response(),
        Err(error) => internal(error),
    }
}

async fn start(
    db: &Db,
    redirect_uri: &str,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: String,
    scope: Option<String>,
) -> anyhow::Result<String> {
    let now = db::now();
    // Sweeping here keeps an idle server idle.
    sqlx::query("DELETE FROM sign_ins WHERE created_at < $1")
        .bind(now - SIGN_IN_LIFETIME)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM sign_in_codes WHERE expires_at < $1")
        .bind(now)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM authorization_codes WHERE expires_at < $1")
        .bind(now)
        .execute(db)
        .await?;
    // A day is the longest window a limit counts in.
    sqlx::query("DELETE FROM code_limits WHERE started_at < $1")
        .bind(now - DAY)
        .execute(db)
        .await?;
    let id = db::random_id();
    sqlx::query(
        "INSERT INTO sign_ins (id, client_id, redirect_uri, state, nonce, code_challenge, scope, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(CLIENT_ID)
    .bind(redirect_uri)
    .bind(state)
    .bind(nonce)
    .bind(code_challenge)
    .bind(scope.unwrap_or_else(|| "openid".into()))
    .bind(now)
    .execute(db)
    .await?;
    Ok(id)
}

/// The sign-in in progress. Once it's finished, its pages lead to the done page.
async fn current(state: &Shared, headers: &HeaderMap) -> Result<SignIn, Response> {
    let sign_in = any(state, headers).await?;
    if sign_in.finished_url.is_some() {
        return Err(Redirect::to("/authorize/done").into_response());
    }
    Ok(sign_in)
}

async fn any(state: &Shared, headers: &HeaderMap) -> Result<SignIn, Response> {
    let id = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(COOKIE)?.strip_prefix('='));
    let expired = || {
        (
            StatusCode::BAD_REQUEST,
            pages::failure("This sign-in has expired."),
        )
            .into_response()
    };
    let Some(id) = id else { return Err(expired()) };
    let sign_in: Option<SignIn> = sqlx::query_as(
        "SELECT id, client_id, redirect_uri, state, nonce, code_challenge, scope, email, account_id, ceremony, \
         codes_sent, finished_url FROM sign_ins WHERE id = $1 AND created_at > $2",
    )
    .bind(id)
    .bind(db::now() - SIGN_IN_LIFETIME)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| internal(error.into()))?;
    sign_in.ok_or_else(expired)
}

#[derive(Deserialize)]
pub struct EmailForm {
    email: String,
}

pub async fn email(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<EmailForm>,
) -> Response {
    let client = client(&state, &headers, peer);
    let sign_in = match current(&state, &headers).await {
        Ok(sign_in) => sign_in,
        Err(response) => return response,
    };
    let Some(email) = super::normalize_email(&form.email) else {
        return pages::email(Some(&form.email), Some("That isn't an email address."));
    };
    let result: anyhow::Result<Response> = async {
        // A corrected address gets its own code and its own resend.
        sqlx::query(
            "UPDATE sign_ins SET codes_sent = CASE WHEN email = $1 THEN codes_sent ELSE 0 END, \
             email = $1, account_id = NULL, ceremony = NULL WHERE id = $2",
        )
        .bind(&email)
        .bind(&sign_in.id)
        .execute(&state.db)
        .await?;
        // Every address gets a code, so the answer doesn't say which have
        // accounts. A passkey signs in from the email page, before any address.
        send_code(&state, &sign_in.id, &email, &client, false).await
    }
    .await;
    result.unwrap_or_else(internal)
}

pub async fn send_code_again(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let client = client(&state, &headers, peer);
    match current(&state, &headers).await {
        Ok(SignIn {
            id,
            email: Some(email),
            codes_sent,
            ..
        }) => send_code(&state, &id, &email, &client, codes_sent > 0)
            .await
            .unwrap_or_else(internal),
        Ok(_) => pages::email(None, None),
        Err(response) => response,
    }
}

/// Who asks for codes, as the limits count it: the address the proxy in front names, else the
/// connection's. An IPv6 client counts by its /64, which one network can hand out at will.
fn client(state: &Shared, headers: &HeaderMap, peer: SocketAddr) -> String {
    let named = (state.config.client_ip_header.as_deref())
        .and_then(|header| headers.get(header)?.to_str().ok())
        // The last address in a list is the one the proxy itself saw.
        .and_then(|addresses| addresses.rsplit(',').next()?.trim().parse::<IpAddr>().ok());
    match named.unwrap_or(peer.ip()).to_canonical() {
        IpAddr::V4(ip) => format!("client {ip}"),
        IpAddr::V6(ip) => {
            let [a, b, c, d, ..] = ip.segments();
            format!("client {a:x}:{b:x}:{c:x}:{d:x}::/64")
        }
    }
}

async fn send_code(
    state: &Shared,
    sign_in: &str,
    email: &str,
    client: &str,
    again: bool,
) -> anyhow::Result<Response> {
    let now = db::now();
    // Reloading the page or pressing twice doesn't mail again.
    let recent: Option<i64> =
        sqlx::query_scalar("SELECT sent_at FROM sign_in_codes WHERE email = $1 AND sent_at > $2")
            .bind(email)
            .bind(now - CODE_RESEND_AFTER)
            .fetch_optional(&state.db)
            .await?;
    if recent.is_some() {
        let note = again.then_some("We sent a code a moment ago. It can take a minute to arrive.");
        return code_page(state, sign_in, email, note, None).await;
    }
    if let Some(refused) = take_codes(state, email, client, now).await? {
        return Ok(pages::email(Some(email), Some(refused)));
    }
    let sent: Option<i64> = sqlx::query_scalar(
        "UPDATE sign_ins SET codes_sent = codes_sent + 1 WHERE id = $1 AND codes_sent < $2 RETURNING codes_sent",
    )
    .bind(sign_in)
    .bind(CODES_PER_SIGN_IN)
    .fetch_optional(&state.db)
    .await?;
    let Some(sent) = sent else {
        give_back_codes(state, email, client).await?;
        return code_page(
            state,
            sign_in,
            email,
            None,
            Some("We can't send another code. If it hasn't arrived, start again from ilo."),
        )
        .await;
    };
    let code = format!(
        "{:06}",
        u64::from_le_bytes(db::random_bytes::<8>()) % 1_000_000
    );
    sqlx::query(
        "INSERT INTO sign_in_codes (email, code_hash, sent_at, expires_at, attempts) VALUES ($1, $2, $3, $4, 0) \
         ON CONFLICT (email) DO UPDATE SET code_hash = excluded.code_hash, sent_at = excluded.sent_at, \
         expires_at = excluded.expires_at, attempts = 0",
    )
    .bind(email)
    .bind(db::hash(&code))
    .bind(now)
    .bind(now + CODE_LIFETIME)
    .execute(&state.db)
    .await?;
    if let Err(error) = state.mailer.send_code(email, &code).await {
        tracing::warn!(%error, "can't mail a sign-in code");
        sqlx::query("DELETE FROM sign_in_codes WHERE email = $1")
            .bind(email)
            .execute(&state.db)
            .await?;
        sqlx::query("UPDATE sign_ins SET codes_sent = codes_sent - 1 WHERE id = $1")
            .bind(sign_in)
            .execute(&state.db)
            .await?;
        give_back_codes(state, email, client).await?;
        return Ok(pages::email(
            Some(email),
            Some("The server couldn't send mail. Try again in a moment."),
        ));
    }
    let note = (sent > 1).then_some("We sent a new code.");
    code_page(state, sign_in, email, note, None).await
}

/// Takes a code from each limit, the address's, the client's and the server's, or none and says
/// which refused.
async fn take_codes(
    state: &Shared,
    email: &str,
    client: &str,
    now: i64,
) -> anyhow::Result<Option<&'static str>> {
    let config = &state.config;
    let limits = [
        (
            format!("address {email}"),
            HOUR,
            CODES_PER_ADDRESS_PER_HOUR,
            "We've sent this address too many codes. Try again in an hour.",
        ),
        (
            client.to_owned(),
            HOUR,
            config.codes_per_client_per_hour,
            "We've sent too many codes to sign-ins from your network. Try again in an hour.",
        ),
        (
            "all".to_owned(),
            DAY,
            config.codes_per_day,
            "The server has sent all the codes it can for today. Try again later.",
        ),
    ];
    for (index, (name, window, limit, refused)) in limits.iter().enumerate() {
        if !take(&state.db, name, now, *window, *limit).await? {
            for (name, ..) in &limits[..index] {
                give_back(&state.db, name).await?;
            }
            return Ok(Some(refused));
        }
    }
    Ok(None)
}

/// Gives back the codes `take_codes` took for a mail that was never sent.
async fn give_back_codes(state: &Shared, email: &str, client: &str) -> anyhow::Result<()> {
    for name in [&format!("address {email}"), client, "all"] {
        give_back(&state.db, name).await?;
    }
    Ok(())
}

/// Takes one of the `limit` codes `name` has in its window, if one is left. One statement locks
/// its row, so sign-ins asking at once can't all read a count under the limit before any of them
/// adds to it.
async fn take(db: &Db, name: &str, now: i64, window: i64, limit: i64) -> anyhow::Result<bool> {
    let taken: Option<i64> = sqlx::query_scalar(
        "INSERT INTO code_limits (name, started_at, sent) VALUES ($1, $2, 1) \
         ON CONFLICT (name) DO UPDATE SET \
         sent = CASE WHEN code_limits.started_at <= $3 THEN 1 ELSE code_limits.sent + 1 END, \
         started_at = CASE WHEN code_limits.started_at <= $3 THEN $2 \
         ELSE code_limits.started_at END \
         WHERE code_limits.started_at <= $3 OR code_limits.sent < $4 \
         RETURNING sent",
    )
    .bind(name)
    .bind(now)
    .bind(now - window)
    .bind(limit)
    .fetch_optional(db)
    .await?;
    Ok(taken.is_some())
}

async fn give_back(db: &Db, name: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE code_limits SET sent = sent - 1 WHERE name = $1 AND sent > 0")
        .bind(name)
        .execute(db)
        .await?;
    Ok(())
}

/// The code page, saying when the code expires and whether a new one can be sent.
async fn code_page(
    state: &Shared,
    sign_in: &str,
    email: &str,
    note: Option<&str>,
    error: Option<&str>,
) -> anyhow::Result<Response> {
    let codes_sent: i64 = sqlx::query_scalar("SELECT codes_sent FROM sign_ins WHERE id = $1")
        .bind(sign_in)
        .fetch_one(&state.db)
        .await?;
    let expires_at: Option<i64> =
        sqlx::query_scalar("SELECT expires_at FROM sign_in_codes WHERE email = $1")
            .bind(email)
            .fetch_optional(&state.db)
            .await?;
    let left = expires_at.map_or(0, |at| at - db::now());
    let page = pages::code(pages::Code {
        email,
        minutes: (left + 59) / 60,
        resend: codes_sent < CODES_PER_SIGN_IN,
        note,
        error,
    });
    Ok(if error.is_some() {
        (StatusCode::BAD_REQUEST, page).into_response()
    } else {
        page
    })
}

#[derive(Deserialize)]
pub struct CodeForm {
    code: String,
}

pub async fn code(
    State(state): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Response {
    let sign_in = match current(&state, &headers).await {
        Ok(sign_in) => sign_in,
        Err(response) => return response,
    };
    let Some(email) = sign_in.email.clone() else {
        return pages::email(None, None);
    };
    let can_resend = sign_in.codes_sent < CODES_PER_SIGN_IN;
    let result: anyhow::Result<Response> = async {
        let now = db::now();
        // Counting the try in the same statement that reads the code, so tries
        // sent at once can't all be checked before any is counted.
        let code_hash: Option<String> = sqlx::query_scalar(
            "UPDATE sign_in_codes SET attempts = attempts + 1 \
             WHERE email = $1 AND expires_at > $2 AND attempts < $3 RETURNING code_hash",
        )
        .bind(&email)
        .bind(now)
        .bind(CODE_ATTEMPTS)
        .fetch_optional(&state.db)
        .await?;
        let refused = |error| code_page(&state, &sign_in.id, &email, None, Some(error));
        let Some(code_hash) = code_hash else {
            let live: Option<i64> = sqlx::query_scalar(
                "SELECT attempts FROM sign_in_codes WHERE email = $1 AND expires_at > $2",
            )
            .bind(&email)
            .bind(now)
            .fetch_optional(&state.db)
            .await?;
            return refused(match (live.is_some(), can_resend) {
                (true, true) => "Too many tries. Send a new code.",
                (true, false) => "Too many tries. Start again from ilo.",
                (false, true) => "That code has expired. Send a new one.",
                (false, false) => "That code has expired. Start again from ilo.",
            })
            .await;
        };
        let typed: String = form.code.chars().filter(|c| !c.is_whitespace()).collect();
        if db::hash(&typed) != code_hash {
            return refused("That code isn't right.").await;
        }
        // Only one of two tries with the right code signs in.
        let used = sqlx::query("DELETE FROM sign_in_codes WHERE email = $1 AND code_hash = $2")
            .bind(&email)
            .bind(&code_hash)
            .execute(&state.db)
            .await?;
        if used.rows_affected() == 0 {
            return refused("That code has already been used. Start again from ilo.").await;
        }
        let account = super::find_or_create(&state.db, &email).await?;
        sqlx::query("UPDATE sign_ins SET account_id = $1 WHERE id = $2")
            .bind(&account)
            .bind(&sign_in.id)
            .execute(&state.db)
            .await?;
        if super::passkeys(&state.db, &account).await?.is_empty()
            && offer_passkey(&state.db, &account).await?
        {
            return Ok(pages::add_passkey());
        }
        finish(&state, &sign_in, &account).await?;
        Ok(to_done())
    }
    .await;
    result.unwrap_or_else(internal)
}

/// Whether to offer a passkey: once per account, after its first sign-in, so
/// "Not now" isn't asked again at every sign-in after.
async fn offer_passkey(db: &Db, account: &str) -> anyhow::Result<bool> {
    let marked = sqlx::query(
        "UPDATE accounts SET passkey_offered = 1 WHERE id = $1 AND passkey_offered = 0",
    )
    .bind(account)
    .execute(db)
    .await?;
    Ok(marked.rows_affected() == 1)
}

/// "Not now" on the passkey page.
pub async fn skip_passkey(State(state): State<Shared>, headers: HeaderMap) -> Response {
    match current(&state, &headers).await {
        Ok(sign_in) => match sign_in.account_id.clone() {
            Some(account) => finish(&state, &sign_in, &account)
                .await
                .map(|()| to_done())
                .unwrap_or_else(internal),
            None => pages::email(sign_in.email.as_deref(), None),
        },
        Err(response) => response,
    }
}

/// Forms end on the done page rather than redirecting straight to the app:
/// `form-action 'self'` covers a form's redirects too, and the page shows the
/// user where they are going.
fn to_done() -> Response {
    Redirect::to("/authorize/done").into_response()
}

/// Ends the sign-in with an authorization code for the app to exchange at
/// `/token`, which the done page hands it.
async fn finish(state: &Shared, sign_in: &SignIn, account: &str) -> anyhow::Result<()> {
    let code = db::random_id();
    sqlx::query(
        "INSERT INTO authorization_codes (code_hash, client_id, redirect_uri, nonce, code_challenge, scope, account_id, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(db::hash(&code))
    .bind(&sign_in.client_id)
    .bind(&sign_in.redirect_uri)
    .bind(&sign_in.nonce)
    .bind(&sign_in.code_challenge)
    .bind(&sign_in.scope)
    .bind(account)
    .bind(db::now() + AUTHORIZATION_CODE_LIFETIME)
    .execute(&state.db)
    .await?;
    let issuer = state.config.issuer();
    let mut reply = vec![("code", code.as_str()), ("iss", issuer.as_str())];
    if let Some(sent) = sign_in.state.as_deref() {
        reply.push(("state", sent));
    }
    sqlx::query("UPDATE sign_ins SET finished_url = $1, ceremony = NULL WHERE id = $2")
        .bind(redirect_with(&sign_in.redirect_uri, &reply))
        .bind(&sign_in.id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// The done page, once: it ends the sign-in and takes the tab back to the app.
pub async fn done(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let sign_in = match any(&state, &headers).await {
        Ok(sign_in) => sign_in,
        Err(response) => return response,
    };
    let (Some(url), Some(email)) = (sign_in.finished_url, sign_in.email) else {
        return (
            StatusCode::BAD_REQUEST,
            pages::failure("This sign-in isn't finished."),
        )
            .into_response();
    };
    let deleted = sqlx::query("DELETE FROM sign_ins WHERE id = $1")
        .bind(&sign_in.id)
        .execute(&state.db)
        .await;
    if let Err(error) = deleted {
        return internal(error.into());
    }
    (
        [(header::SET_COOKIE, cookie(&state.config, "", 0))],
        pages::done(&email, &url),
    )
        .into_response()
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn json_internal(error: anyhow::Error) -> Response {
    tracing::error!(%error, "a passkey ceremony failed");
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong on the server.",
    )
}

async fn save_ceremony(db: &Db, sign_in: &str, ceremony: Option<String>) -> anyhow::Result<()> {
    sqlx::query("UPDATE sign_ins SET ceremony = $1 WHERE id = $2")
        .bind(ceremony)
        .bind(sign_in)
        .execute(db)
        .await?;
    Ok(())
}

fn finished() -> Response {
    Json(json!({ "redirect": "/authorize/done" })).into_response()
}

pub async fn register_start(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let sign_in = match current(&state, &headers).await {
        Ok(sign_in) => sign_in,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "This sign-in has expired."),
    };
    let Some(account) = sign_in.account_id.clone() else {
        return json_error(StatusCode::BAD_REQUEST, "Sign in with a code first.");
    };
    let result: anyhow::Result<Response> = async {
        let email = super::email(&state.db, &account).await?;
        let existing = super::passkeys(&state.db, &account).await?;
        let exclude = existing
            .iter()
            .map(|passkey| passkey.cred_id().clone())
            .collect();
        let (options, registration) = state.webauthn.start_passkey_registration(
            Uuid::parse_str(&account)?,
            &email,
            &email,
            Some(exclude),
        )?;
        // Discoverable, so signing in can ask the authenticator which account
        // it holds instead of the server naming an address's credentials.
        // Finishing doesn't check this, so the ceremony itself is unchanged.
        let mut options = serde_json::to_value(options)?;
        let selection = &mut options["publicKey"]["authenticatorSelection"];
        selection["residentKey"] = json!("required");
        selection["requireResidentKey"] = json!(true);
        save_ceremony(
            &state.db,
            &sign_in.id,
            Some(serde_json::to_string(&registration)?),
        )
        .await?;
        Ok(Json(options).into_response())
    }
    .await;
    result.unwrap_or_else(json_internal)
}

pub async fn register_finish(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(credential): Json<RegisterPublicKeyCredential>,
) -> Response {
    let sign_in = match current(&state, &headers).await {
        Ok(sign_in) => sign_in,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "This sign-in has expired."),
    };
    let (Some(account), Some(ceremony)) = (sign_in.account_id.clone(), sign_in.ceremony.clone())
    else {
        return json_error(StatusCode::BAD_REQUEST, "Start adding the passkey again.");
    };
    let result: anyhow::Result<Response> = async {
        save_ceremony(&state.db, &sign_in.id, None).await?;
        let registration: PasskeyRegistration = serde_json::from_str(&ceremony)?;
        let passkey = match state.webauthn.finish_passkey_registration(&credential, &registration) {
            Ok(passkey) => passkey,
            Err(error) => {
                tracing::info!(%error, "a passkey registration was refused");
                return Ok(json_error(StatusCode::BAD_REQUEST, "The passkey couldn't be added."));
            }
        };
        sqlx::query("INSERT INTO passkeys (credential_id, account_id, passkey, created_at) VALUES ($1, $2, $3, $4)")
            .bind(credential_id(passkey.cred_id()))
            .bind(&account)
            .bind(serde_json::to_string(&passkey)?)
            .bind(db::now())
            .execute(&state.db)
            .await?;
        finish(&state, &sign_in, &account).await?;
        Ok(finished())
    }
    .await;
    result.unwrap_or_else(json_internal)
}

fn credential_id(id: &impl AsRef<[u8]>) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id)
}

/// Starts a passkey sign-in without an address: the authenticator offers the
/// passkeys it holds for ilo, so the server names no account's credentials.
pub async fn login_start(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let sign_in = match current(&state, &headers).await {
        Ok(sign_in) => sign_in,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "This sign-in has expired."),
    };
    let result: anyhow::Result<Response> = async {
        let (mut options, authentication) = state.webauthn.start_discoverable_authentication()?;
        // The page asks when the button is pressed, not from the email field's autofill.
        options.mediation = None;
        save_ceremony(
            &state.db,
            &sign_in.id,
            Some(serde_json::to_string(&authentication)?),
        )
        .await?;
        Ok(Json(options).into_response())
    }
    .await;
    result.unwrap_or_else(json_internal)
}

pub async fn login_finish(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(credential): Json<PublicKeyCredential>,
) -> Response {
    let sign_in = match current(&state, &headers).await {
        Ok(sign_in) => sign_in,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "This sign-in has expired."),
    };
    let Some(ceremony) = sign_in.ceremony.clone() else {
        return json_error(StatusCode::BAD_REQUEST, "Start the passkey sign-in again.");
    };
    let refused = || json_error(StatusCode::BAD_REQUEST, "The passkey wasn't accepted.");
    let result: anyhow::Result<Response> = async {
        save_ceremony(&state.db, &sign_in.id, None).await?;
        let authentication: DiscoverableAuthentication = serde_json::from_str(&ceremony)?;
        // The passkey names its account; only that account's passkeys can sign it.
        let Ok((user, _)) = state
            .webauthn
            .identify_discoverable_authentication(&credential)
        else {
            return Ok(refused());
        };
        let account = user.to_string();
        let passkeys = super::passkeys(&state.db, &account).await?;
        let keys: Vec<DiscoverableKey> = passkeys.iter().map(DiscoverableKey::from).collect();
        let outcome = match state.webauthn.finish_discoverable_authentication(
            &credential,
            authentication,
            &keys,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::info!(%error, "a passkey sign-in was refused");
                return Ok(refused());
            }
        };
        // The counter and backup state change with each use.
        for mut passkey in passkeys {
            if passkey.update_credential(&outcome) == Some(true) {
                sqlx::query("UPDATE passkeys SET passkey = $1 WHERE credential_id = $2")
                    .bind(serde_json::to_string(&passkey)?)
                    .bind(credential_id(passkey.cred_id()))
                    .execute(&state.db)
                    .await?;
            }
        }
        // The done page names the account signed in to, whatever address was typed.
        sqlx::query("UPDATE sign_ins SET email = $1, account_id = $2 WHERE id = $3")
            .bind(super::email(&state.db, &account).await?)
            .bind(&account)
            .bind(&sign_in.id)
            .execute(&state.db)
            .await?;
        finish(&state, &sign_in, &account).await?;
        Ok(finished())
    }
    .await;
    result.unwrap_or_else(json_internal)
}

pub async fn signed_in() -> Response {
    pages::signed_in()
}
