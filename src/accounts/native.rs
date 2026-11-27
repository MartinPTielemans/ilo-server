//! `/native/sign-in`: the mailed-code road for an app that draws the address and the code in its
//! own window, with no page. It shares the page's sign-in rows, limits and codes
//! (`super::sign_in`), and ends with `/token`'s own answer.
//!
//! The app starts with a PKCE challenge, and only the verifier gets the tokens, so the sign-in's
//! id alone can't spend a try. JSON only, and no CORS, so no web page can call it. Nothing here
//! logs an address, a code, a verifier or a sign-in's id.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};

use super::sign_in::{
    self, CLIENT_ID, CODE_LIFETIME, CODE_RESEND_AFTER, CODES_PER_SIGN_IN, Checked, Limit, Sent,
};
use crate::Shared;

/// What the app asks with, as `/authorize` asks for "openid email offline_access".
const SCOPE: &str = "openid email offline_access";

fn answer(status: StatusCode, body: Value) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

fn refused(status: StatusCode, error: &str) -> Response {
    answer(status, json!({ "error": error }))
}

/// A fixed sentence: the error may carry what was asked.
fn internal(_: anyhow::Error) -> Response {
    tracing::error!("a native sign-in failed on the server");
    refused(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
}

fn limit(limit: Limit) -> Response {
    refused(
        StatusCode::TOO_MANY_REQUESTS,
        match limit {
            Limit::Address => "limit_address",
            Limit::Client => "limit_client",
            Limit::Server => "limit_server",
        },
    )
}

/// The answer to a code mailed or standing: alike for every address, whether or not it has an
/// account.
fn waiting(sign_in: &str, codes_sent: i64) -> Response {
    answer(
        StatusCode::OK,
        json!({
            "sign_in": sign_in,
            "resend_in": CODE_RESEND_AFTER,
            "expires_in": CODE_LIFETIME,
            "can_resend": codes_sent < CODES_PER_SIGN_IN,
        }),
    )
}

#[derive(Deserialize)]
pub struct Start {
    client_id: String,
    code_challenge: String,
    code_challenge_method: String,
    email: String,
}

pub async fn start(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(asked): Json<Start>,
) -> Response {
    if asked.client_id != CLIENT_ID {
        return refused(StatusCode::BAD_REQUEST, "invalid_client");
    }
    // A SHA-256 in base64url without padding is 43 characters.
    if asked.code_challenge_method != "S256" || asked.code_challenge.len() != 43 {
        return refused(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Some(email) = super::normalize_email(&asked.email) else {
        return refused(StatusCode::BAD_REQUEST, "invalid_email");
    };
    let domain = email.rsplit_once('@').map_or("", |(_, domain)| domain);
    if !state.domains.take_mail(domain).await {
        return refused(StatusCode::BAD_REQUEST, "undeliverable");
    }
    let client = sign_in::client(&state, &headers, peer);
    let result: anyhow::Result<Response> = async {
        let redirect = state.config.url("/signed-in");
        let id = sign_in::start(
            &state.db,
            &redirect,
            None,
            None,
            asked.code_challenge,
            Some(SCOPE.to_owned()),
        )
        .await?;
        sqlx::query("UPDATE sign_ins SET email = $1 WHERE id = $2")
            .bind(&email)
            .bind(&id)
            .execute(&state.db)
            .await?;
        mailed(&state, &id, &email, &client).await
    }
    .await;
    result.unwrap_or_else(internal)
}

/// Mails the sign-in its code and says so, or why not.
async fn mailed(state: &Shared, id: &str, email: &str, client: &str) -> anyhow::Result<Response> {
    let sent = sign_in::mail_code(state, id, email, client).await?;
    let codes_sent: i64 = sqlx::query_scalar("SELECT codes_sent FROM sign_ins WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await?;
    Ok(match sent {
        // A code mailed to the address moments ago, for this sign-in or another, still stands.
        Sent::Mailed { .. } | Sent::Recent => waiting(id, codes_sent),
        Sent::Refused(refused) => limit(refused),
        Sent::NoMore => refused(StatusCode::TOO_MANY_REQUESTS, "no_more_codes"),
        Sent::MailFailed => refused(StatusCode::BAD_GATEWAY, "mail_failed"),
    })
}

#[derive(Deserialize)]
pub struct Resend {
    sign_in: String,
}

pub async fn resend(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(asked): Json<Resend>,
) -> Response {
    let client = sign_in::client(&state, &headers, peer);
    let result: anyhow::Result<Response> = async {
        let Some(sign_in) = sign_in::by_id(&state, &asked.sign_in)
            .await?
            .filter(|sign_in| sign_in.finished_url.is_none())
        else {
            return Ok(refused(StatusCode::BAD_REQUEST, "sign_in_expired"));
        };
        let Some(email) = sign_in.email else {
            return Ok(refused(StatusCode::BAD_REQUEST, "sign_in_expired"));
        };
        mailed(&state, &sign_in.id, &email, &client).await
    }
    .await;
    result.unwrap_or_else(internal)
}

#[derive(Deserialize)]
pub struct Code {
    sign_in: String,
    code: String,
    code_verifier: String,
    device_name: Option<String>,
}

pub async fn code(State(state): State<Shared>, Json(asked): Json<Code>) -> Response {
    let result: anyhow::Result<Response> = async {
        let Some(sign_in) = sign_in::by_id(&state, &asked.sign_in)
            .await?
            .filter(|sign_in| sign_in.finished_url.is_none())
        else {
            return Ok(refused(StatusCode::BAD_REQUEST, "sign_in_expired"));
        };
        // Before the code is read, so without the verifier no try is spent.
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(openssl::sha::sha256(asked.code_verifier.as_bytes()));
        if challenge != sign_in.code_challenge {
            return Ok(refused(StatusCode::BAD_REQUEST, "invalid_grant"));
        }
        let Some(email) = sign_in.email.clone() else {
            return Ok(refused(StatusCode::BAD_REQUEST, "sign_in_expired"));
        };
        let can_resend = sign_in.codes_sent < CODES_PER_SIGN_IN;
        let wrong = |error: &str| {
            answer(
                StatusCode::BAD_REQUEST,
                json!({ "error": error, "can_resend": can_resend }),
            )
        };
        match sign_in::check_code(&state, &email, &asked.code).await? {
            Checked::Right => {}
            Checked::Wrong => return Ok(wrong("wrong_code")),
            Checked::TooMany => return Ok(wrong("too_many_tries")),
            Checked::Expired => return Ok(wrong("expired")),
            Checked::Used => return Ok(wrong("used")),
        }
        let account = super::find_or_create(&state.db, &email).await?;
        let code = sign_in::finish(&state, &sign_in, &account).await?;
        // Ended here, as the done page ends a page's sign-in.
        sqlx::query("DELETE FROM sign_ins WHERE id = $1")
            .bind(&sign_in.id)
            .execute(&state.db)
            .await?;
        super::oidc::exchange(
            &state,
            code,
            asked.code_verifier,
            sign_in.redirect_uri,
            asked.device_name,
        )
        .await
    }
    .await;
    result.unwrap_or_else(internal)
}
