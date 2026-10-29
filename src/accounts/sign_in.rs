//! `/authorize`: the pages between ilo opening a sign-in tab and the redirect
//! that hands it an authorization code.
//!
//! A cookie names the sign-in, so its pages work only in the browser that
//! started it.

use axum::Json;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::json;
use url::Url;
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    Uuid,
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

async fn current(state: &Shared, headers: &HeaderMap) -> Result<SignIn, Response> {
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
        "SELECT id, client_id, redirect_uri, state, nonce, code_challenge, scope, email, account_id, ceremony \
         FROM sign_ins WHERE id = $1 AND created_at > $2",
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
    headers: HeaderMap,
    Form(form): Form<EmailForm>,
) -> Response {
    let sign_in = match current(&state, &headers).await {
        Ok(sign_in) => sign_in,
        Err(response) => return response,
    };
    let Some(email) = super::normalize_email(&form.email) else {
        return pages::email(Some(&form.email), Some("That isn't an email address."));
    };
    let result: anyhow::Result<Response> = async {
        sqlx::query(
            "UPDATE sign_ins SET email = $1, account_id = NULL, ceremony = NULL WHERE id = $2",
        )
        .bind(&email)
        .bind(&sign_in.id)
        .execute(&state.db)
        .await?;
        if let Some(account) = super::find_by_email(&state.db, &email).await? {
            if !super::passkeys(&state.db, &account).await?.is_empty() {
                return Ok(pages::choose(&email));
            }
        }
        send_code(&state, &email).await
    }
    .await;
    result.unwrap_or_else(internal)
}

pub async fn send_code_again(State(state): State<Shared>, headers: HeaderMap) -> Response {
    match current(&state, &headers).await {
        Ok(SignIn {
            email: Some(email), ..
        }) => send_code(&state, &email).await.unwrap_or_else(internal),
        Ok(_) => pages::email(None, None),
        Err(response) => response,
    }
}

async fn send_code(state: &Shared, email: &str) -> anyhow::Result<Response> {
    let now = db::now();
    // Reloading the page or pressing twice doesn't mail again.
    let recent: Option<i64> =
        sqlx::query_scalar("SELECT sent_at FROM sign_in_codes WHERE email = $1 AND sent_at > $2")
            .bind(email)
            .bind(now - CODE_RESEND_AFTER)
            .fetch_optional(&state.db)
            .await?;
    if recent.is_some() {
        return Ok(pages::code(email, None));
    }
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
        return Ok(pages::email(
            Some(email),
            Some("The server couldn't send mail. Try again in a moment."),
        ));
    }
    Ok(pages::code(email, None))
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
    let result: anyhow::Result<Response> = async {
        let row: Option<(String, i64, i64)> = sqlx::query_as(
            "SELECT code_hash, expires_at, attempts FROM sign_in_codes WHERE email = $1",
        )
        .bind(&email)
        .fetch_optional(&state.db)
        .await?;
        let Some((code_hash, _, attempts)) =
            row.filter(|(_, expires_at, _)| *expires_at > db::now())
        else {
            return Ok(pages::code(
                &email,
                Some("That code has expired. Send a new one."),
            ));
        };
        if attempts >= CODE_ATTEMPTS {
            return Ok(pages::code(
                &email,
                Some("Too many tries. Send a new code."),
            ));
        }
        let typed: String = form.code.chars().filter(|c| !c.is_whitespace()).collect();
        if db::hash(&typed) != code_hash {
            sqlx::query("UPDATE sign_in_codes SET attempts = attempts + 1 WHERE email = $1")
                .bind(&email)
                .execute(&state.db)
                .await?;
            return Ok(pages::code(&email, Some("That code isn't right.")));
        }
        sqlx::query("DELETE FROM sign_in_codes WHERE email = $1")
            .bind(&email)
            .execute(&state.db)
            .await?;
        let account = super::find_or_create(&state.db, &email).await?;
        sqlx::query("UPDATE sign_ins SET account_id = $1 WHERE id = $2")
            .bind(&account)
            .bind(&sign_in.id)
            .execute(&state.db)
            .await?;
        if super::passkeys(&state.db, &account).await?.is_empty() {
            return Ok(pages::add_passkey());
        }
        finish(&state, &sign_in, &account)
            .await
            .map(|url| redirect(&state.config, &url))
    }
    .await;
    result.unwrap_or_else(internal)
}

/// "Not now" on the passkey page.
pub async fn skip_passkey(State(state): State<Shared>, headers: HeaderMap) -> Response {
    match current(&state, &headers).await {
        Ok(sign_in) => match sign_in.account_id.clone() {
            Some(account) => finish(&state, &sign_in, &account)
                .await
                .map(|url| redirect(&state.config, &url))
                .unwrap_or_else(internal),
            None => pages::email(sign_in.email.as_deref(), None),
        },
        Err(response) => response,
    }
}

fn redirect(config: &Config, url: &str) -> Response {
    (
        [(header::SET_COOKIE, cookie(config, "", 0))],
        Redirect::to(url),
    )
        .into_response()
}

/// Ends the sign-in with an authorization code for the app to exchange at `/token`.
async fn finish(state: &Shared, sign_in: &SignIn, account: &str) -> anyhow::Result<String> {
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
    sqlx::query("DELETE FROM sign_ins WHERE id = $1")
        .bind(&sign_in.id)
        .execute(&state.db)
        .await?;
    let issuer = state.config.issuer();
    let mut reply = vec![("code", code.as_str()), ("iss", issuer.as_str())];
    if let Some(sent) = sign_in.state.as_deref() {
        reply.push(("state", sent));
    }
    Ok(redirect_with(&sign_in.redirect_uri, &reply))
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

fn finished(config: &Config, url: String) -> Response {
    (
        [(header::SET_COOKIE, cookie(config, "", 0))],
        Json(json!({ "redirect": url })),
    )
        .into_response()
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
        Ok(finished(&state.config, finish(&state, &sign_in, &account).await?))
    }
    .await;
    result.unwrap_or_else(json_internal)
}

fn credential_id(id: &impl AsRef<[u8]>) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id)
}

pub async fn login_start(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let sign_in = match current(&state, &headers).await {
        Ok(sign_in) => sign_in,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "This sign-in has expired."),
    };
    let Some(email) = sign_in.email.clone() else {
        return json_error(StatusCode::BAD_REQUEST, "Enter your email first.");
    };
    let result: anyhow::Result<Response> = async {
        let Some(account) = super::find_by_email(&state.db, &email).await? else {
            return Ok(json_error(
                StatusCode::BAD_REQUEST,
                "This account has no passkey.",
            ));
        };
        let passkeys = super::passkeys(&state.db, &account).await?;
        if passkeys.is_empty() {
            return Ok(json_error(
                StatusCode::BAD_REQUEST,
                "This account has no passkey.",
            ));
        }
        let (options, authentication) = state.webauthn.start_passkey_authentication(&passkeys)?;
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
    let (Some(email), Some(ceremony)) = (sign_in.email.clone(), sign_in.ceremony.clone()) else {
        return json_error(StatusCode::BAD_REQUEST, "Start the passkey sign-in again.");
    };
    let result: anyhow::Result<Response> = async {
        save_ceremony(&state.db, &sign_in.id, None).await?;
        let authentication: PasskeyAuthentication = serde_json::from_str(&ceremony)?;
        let outcome = match state
            .webauthn
            .finish_passkey_authentication(&credential, &authentication)
        {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::info!(%error, "a passkey sign-in was refused");
                return Ok(json_error(
                    StatusCode::BAD_REQUEST,
                    "The passkey wasn't accepted.",
                ));
            }
        };
        let account = super::find_by_email(&state.db, &email)
            .await?
            .ok_or_else(|| anyhow::anyhow!("account gone"))?;
        // The counter and backup state change with each use.
        for mut passkey in super::passkeys(&state.db, &account).await? {
            if passkey.update_credential(&outcome) == Some(true) {
                sqlx::query("UPDATE passkeys SET passkey = $1 WHERE credential_id = $2")
                    .bind(serde_json::to_string(&passkey)?)
                    .bind(credential_id(passkey.cred_id()))
                    .execute(&state.db)
                    .await?;
            }
        }
        Ok(finished(
            &state.config,
            finish(&state, &sign_in, &account).await?,
        ))
    }
    .await;
    result.unwrap_or_else(json_internal)
}

pub async fn signed_in() -> Response {
    pages::signed_in()
}
