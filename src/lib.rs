//! ilo's account, sync and relay server.

// Handlers return a ready response as their error; boxing it would buy nothing.
#![allow(clippy::result_large_err)]

pub mod accounts;
pub mod config;
pub mod db;
mod jwt;
pub mod mail;
pub mod pairing;
pub mod relay;
pub mod sync;
pub mod tokens;

/// Chromium's sync protocol, generated from `proto/` by `build.rs`.
#[allow(clippy::all, clippy::pedantic)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/sync_pb.rs"));
}

use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use accounts::{devices, oidc, sign_in};
use config::Config;
use mail::Mailer;

pub struct AppState {
    pub config: Config,
    pub db: db::Db,
    pub mailer: Mailer,
    pub relay: relay::Relay,
    webauthn: Webauthn,
    signer: jwt::Signer,
}

pub type Shared = Arc<AppState>;

pub async fn state(config: Config, mailer: Mailer) -> anyhow::Result<Shared> {
    let db = db::connect(&config.database_url).await?;
    let rp_id = config
        .public_url
        .host_str()
        .context("PUBLIC_URL has no host")?;
    let webauthn = WebauthnBuilder::new(rp_id, &config.public_url)
        .context("PUBLIC_URL can't be a passkey origin")?
        .rp_name("ilo")
        .build()?;
    let signer = jwt::Signer::load_or_create(&db).await?;
    Ok(Arc::new(AppState {
        config,
        db,
        mailer,
        relay: relay::Relay::default(),
        webauthn,
        signer,
    }))
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route("/jwks", get(oidc::jwks))
        .route("/authorize", get(sign_in::authorize))
        .route("/authorize/email", post(sign_in::email))
        .route("/authorize/send-code", post(sign_in::send_code_again))
        .route("/authorize/code", post(sign_in::code))
        .route("/authorize/continue", post(sign_in::skip_passkey))
        .route("/authorize/done", get(sign_in::done))
        .route("/authorize/passkey/register", post(sign_in::register_start))
        .route(
            "/authorize/passkey/register/finish",
            post(sign_in::register_finish),
        )
        .route("/authorize/passkey/login", post(sign_in::login_start))
        .route(
            "/authorize/passkey/login/finish",
            post(sign_in::login_finish),
        )
        .route("/sign-in.js", get(accounts::pages_script))
        .route("/sign-in.css", get(accounts::pages_style))
        .route("/signed-in", get(sign_in::signed_in))
        .route("/token", post(oidc::token))
        .route("/userinfo", get(oidc::userinfo).post(oidc::userinfo))
        .route("/revoke", post(oidc::revoke))
        .route("/api/devices", get(devices::list))
        .route("/api/devices/{id}", delete(devices::remove))
        .route("/api/account", delete(devices::delete_account))
        .route(
            "/command/",
            post(sync::command).layer(DefaultBodyLimit::max(sync::MAX_MESSAGE)),
        )
        .route(
            "/command",
            post(sync::command).layer(DefaultBodyLimit::max(sync::MAX_MESSAGE)),
        )
        .route("/relay", get(relay::connect))
        .with_state(state)
}

async fn health(State(state): State<Shared>) -> (StatusCode, &'static str) {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(error) => {
            tracing::error!(%error, "the database isn't answering");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
        }
    }
}
