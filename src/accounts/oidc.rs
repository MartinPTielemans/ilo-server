//! The OpenID Connect endpoints: discovery, keys, `/token`, `/userinfo` and
//! `/revoke`. Each code exchange makes a device, which the tokens belong to.

use axum::Json;
use axum::extract::{Form, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};

use super::sign_in::CLIENT_ID;
use crate::Shared;
use crate::db;
use crate::tokens::{self, Authenticated, Device, Tokens};

pub async fn discovery(State(state): State<Shared>) -> Json<Value> {
    let config = &state.config;
    Json(json!({
        "issuer": config.issuer(),
        "authorization_endpoint": config.url("/authorize"),
        "token_endpoint": config.url("/token"),
        "userinfo_endpoint": config.url("/userinfo"),
        "jwks_uri": config.url("/jwks"),
        "revocation_endpoint": config.url("/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["openid", "email", "offline_access"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "nonce", "email", "email_verified", "sid"],
        "authorization_response_iss_parameter_supported": true,
    }))
}

pub async fn jwks(State(state): State<Shared>) -> Response {
    match state.signer.jwks() {
        Ok(keys) => Json(keys).into_response(),
        Err(error) => {
            tracing::error!(%error, "can't publish the signing key");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    /// Not OIDC's: the name the account's device list shows, such as "MacBook Air".
    device_name: Option<String>,
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

pub async fn token(State(state): State<Shared>, Form(request): Form<TokenRequest>) -> Response {
    let result = match request.grant_type.as_str() {
        "authorization_code" => exchange_code(&state, request).await,
        "refresh_token" => refresh(&state, request).await,
        _ => Ok(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "use authorization_code or refresh_token",
        )),
    };
    result.unwrap_or_else(|error| {
        tracing::error!(%error, "can't issue tokens");
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "try again",
        )
    })
}

#[derive(sqlx::FromRow)]
struct AuthorizationCode {
    client_id: String,
    redirect_uri: String,
    nonce: Option<String>,
    code_challenge: String,
    scope: String,
    account_id: String,
}

async fn exchange_code(state: &Shared, request: TokenRequest) -> anyhow::Result<Response> {
    let invalid = |description| {
        Ok(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            description,
        ))
    };
    let (Some(code), Some(verifier)) = (request.code, request.code_verifier) else {
        return Ok(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code and code_verifier are required",
        ));
    };
    // Deleting it first makes a code work once, even when two requests race.
    let found: Option<AuthorizationCode> = sqlx::query_as(
        "DELETE FROM authorization_codes WHERE code_hash = $1 AND expires_at > $2 \
         RETURNING client_id, redirect_uri, nonce, code_challenge, scope, account_id",
    )
    .bind(db::hash(&code))
    .bind(db::now())
    .fetch_optional(&state.db)
    .await?;
    let Some(found) = found else {
        return invalid("the code is unknown, used or expired");
    };
    if request.client_id.as_deref().unwrap_or(CLIENT_ID) != found.client_id {
        return invalid("the code was issued to another client");
    }
    if request.redirect_uri.as_deref() != Some(found.redirect_uri.as_str()) {
        return invalid("redirect_uri doesn't match the authorization request");
    }
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(openssl::sha::sha256(verifier.as_bytes()));
    if challenge != found.code_challenge {
        return invalid("code_verifier doesn't match the code challenge");
    }
    let name: String = request
        .device_name
        .as_deref()
        .unwrap_or("ilo")
        .trim()
        .chars()
        .take(100)
        .collect();
    let device = Device {
        id: db::random_id(),
        account_id: found.account_id,
    };
    let now = db::now();
    sqlx::query("INSERT INTO devices (id, account_id, name, created_at, last_seen_at) VALUES ($1, $2, $3, $4, $4)")
        .bind(&device.id)
        .bind(&device.account_id)
        .bind(if name.is_empty() { "ilo".to_owned() } else { name })
        .bind(now)
        .execute(&state.db)
        .await?;
    let tokens = tokens::issue(&state.db, &device.id).await?;
    respond(
        state,
        &device,
        &tokens,
        &found.client_id,
        found.nonce.as_deref(),
        &found.scope,
    )
    .await
}

async fn refresh(state: &Shared, request: TokenRequest) -> anyhow::Result<Response> {
    let Some(refresh_token) = request.refresh_token else {
        return Ok(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        ));
    };
    match tokens::refresh(&state.db, &refresh_token).await? {
        Some((device, tokens)) => respond(state, &device, &tokens, CLIENT_ID, None, "openid").await,
        None => Ok(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "the refresh token is unknown, used or expired",
        )),
    }
}

async fn respond(
    state: &Shared,
    device: &Device,
    tokens: &Tokens,
    client_id: &str,
    nonce: Option<&str>,
    scope: &str,
) -> anyhow::Result<Response> {
    let now = db::now();
    let email = super::email(&state.db, &device.account_id).await?;
    let mut claims = json!({
        "iss": state.config.issuer(),
        "sub": device.account_id,
        "aud": client_id,
        "iat": now,
        "exp": now + tokens::ACCESS_LIFETIME,
        "email": email,
        "email_verified": true,
        "sid": device.id,
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "access_token": tokens.access,
            "token_type": "Bearer",
            "expires_in": tokens::ACCESS_LIFETIME,
            "refresh_token": tokens.refresh,
            "id_token": state.signer.sign(&claims)?,
            "scope": scope,
        })),
    )
        .into_response())
}

pub async fn userinfo(
    State(state): State<Shared>,
    Authenticated(device): Authenticated,
) -> Response {
    match super::email(&state.db, &device.account_id).await {
        Ok(email) => {
            Json(json!({ "sub": device.account_id, "email": email, "email_verified": true }))
                .into_response()
        }
        Err(error) => {
            tracing::error!(%error, "can't read an account");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct RevokeRequest {
    token: String,
}

/// RFC 7009: unknown tokens are revoked already, so every answer is 200.
pub async fn revoke(State(state): State<Shared>, Form(request): Form<RevokeRequest>) -> Response {
    match tokens::revoke(&state.db, &request.token).await {
        Ok(Some(device)) => {
            state
                .relay
                .disconnect_device(&device.account_id, &device.id);
            StatusCode::OK.into_response()
        }
        Ok(None) => StatusCode::OK.into_response(),
        Err(error) => {
            tracing::error!(%error, "can't revoke a token");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}
