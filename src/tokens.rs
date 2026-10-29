//! Devices' tokens: what `/token` issues and what sync and the relay accept.
//!
//! Tokens are opaque, stored hashed, and belong to a device; removing the
//! device ends them. ilo's engine hands Chromium's sync the access token as a
//! Bearer header and refreshes it when it expires or gets a 401, so an expired
//! or unknown token is a 401, never a 403. The format stays in this module.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;

use crate::Shared;
use crate::db::{self, Db};

pub const ACCESS_LIFETIME: i64 = 60 * 60;
pub const REFRESH_LIFETIME: i64 = 90 * 24 * 60 * 60;

const ACCESS: &str = "access";
const REFRESH: &str = "refresh";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub account_id: String,
}

pub struct Tokens {
    pub access: String,
    pub refresh: String,
}

fn new_token(prefix: &str) -> String {
    // A prefix lets secret scanners recognise a leaked token.
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(db::random_bytes::<32>());
    format!("{prefix}{secret}")
}

pub async fn issue(db: &Db, device_id: &str) -> anyhow::Result<Tokens> {
    let now = db::now();
    sqlx::query("DELETE FROM tokens WHERE device_id = $1 AND expires_at < $2")
        .bind(device_id)
        .bind(now)
        .execute(db)
        .await?;
    let tokens = Tokens {
        access: new_token("ilo_at_"),
        refresh: new_token("ilo_rt_"),
    };
    for (token, kind, lifetime) in [
        (&tokens.access, ACCESS, ACCESS_LIFETIME),
        (&tokens.refresh, REFRESH, REFRESH_LIFETIME),
    ] {
        sqlx::query(
            "INSERT INTO tokens (token_hash, kind, device_id, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(db::hash(token))
        .bind(kind)
        .bind(device_id)
        .bind(now + lifetime)
        .execute(db)
        .await?;
    }
    Ok(tokens)
}

async fn find(db: &Db, token: &str, kind: &str) -> anyhow::Result<Option<Device>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT devices.id, devices.account_id FROM tokens \
         JOIN devices ON devices.id = tokens.device_id \
         WHERE tokens.token_hash = $1 AND tokens.kind = $2 AND tokens.expires_at > $3",
    )
    .bind(db::hash(token))
    .bind(kind)
    .bind(db::now())
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(id, account_id)| Device { id, account_id }))
}

pub async fn authenticate(db: &Db, access_token: &str) -> anyhow::Result<Option<Device>> {
    find(db, access_token, ACCESS).await
}

/// Swaps a refresh token for new tokens; the old refresh token stops working.
pub async fn refresh(db: &Db, refresh_token: &str) -> anyhow::Result<Option<(Device, Tokens)>> {
    let Some(device) = find(db, refresh_token, REFRESH).await? else {
        return Ok(None);
    };
    sqlx::query("DELETE FROM tokens WHERE token_hash = $1")
        .bind(db::hash(refresh_token))
        .execute(db)
        .await?;
    sqlx::query("UPDATE devices SET last_seen_at = $1 WHERE id = $2")
        .bind(db::now())
        .bind(&device.id)
        .execute(db)
        .await?;
    let tokens = issue(db, &device.id).await?;
    Ok(Some((device, tokens)))
}

/// Revoking a refresh token signs its device out; an access token only ends itself.
pub async fn revoke(db: &Db, token: &str) -> anyhow::Result<Option<Device>> {
    if let Some(device) = find(db, token, REFRESH).await? {
        sqlx::query("DELETE FROM devices WHERE id = $1")
            .bind(&device.id)
            .execute(db)
            .await?;
        return Ok(Some(device));
    }
    sqlx::query("DELETE FROM tokens WHERE token_hash = $1 AND kind = $2")
        .bind(db::hash(token))
        .bind(ACCESS)
        .execute(db)
        .await?;
    Ok(None)
}

pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// A request made with a device's access token.
pub struct Authenticated(pub Device);

impl FromRequestParts<Shared> for Authenticated {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self, Response> {
        let unauthorized = || {
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
            )
                .into_response()
        };
        let token = bearer(&parts.headers).ok_or_else(unauthorized)?;
        match authenticate(&state.db, token).await {
            Ok(Some(device)) => Ok(Self(device)),
            Ok(None) => Err(unauthorized()),
            Err(error) => {
                tracing::error!(%error, "can't check a token");
                Err(StatusCode::SERVICE_UNAVAILABLE.into_response())
            }
        }
    }
}
