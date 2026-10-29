//! The account's devices, and deleting the account, for ilo's Settings.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;

use crate::Shared;
use crate::tokens::Authenticated;

#[derive(Serialize, sqlx::FromRow)]
struct Listed {
    id: String,
    name: String,
    created_at: i64,
    last_seen_at: i64,
}

fn internal(error: impl std::fmt::Display) -> Response {
    tracing::error!(%error, "a device request failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

pub async fn list(State(state): State<Shared>, Authenticated(device): Authenticated) -> Response {
    let listed: Result<Vec<Listed>, _> = sqlx::query_as(
        "SELECT id, name, created_at, last_seen_at FROM devices WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(&device.account_id)
    .fetch_all(&state.db)
    .await;
    match listed {
        Ok(listed) => {
            let devices: Vec<_> = listed
                .into_iter()
                .map(|listed| {
                    let current = listed.id == device.id;
                    let online = state.relay.is_online(&device.account_id, &listed.id);
                    json!({
                        "id": listed.id,
                        "name": listed.name,
                        "created_at": listed.created_at,
                        "last_seen_at": listed.last_seen_at,
                        "current": current,
                        "online": online,
                    })
                })
                .collect();
            Json(json!({ "devices": devices })).into_response()
        }
        Err(error) => internal(error),
    }
}

/// Signs a device out: its tokens stop working and its relay connection closes.
pub async fn remove(
    State(state): State<Shared>,
    Authenticated(device): Authenticated,
    Path(id): Path<String>,
) -> Response {
    let removed = sqlx::query("DELETE FROM devices WHERE id = $1 AND account_id = $2")
        .bind(&id)
        .bind(&device.account_id)
        .execute(&state.db)
        .await;
    match removed {
        Ok(done) if done.rows_affected() == 0 => StatusCode::NOT_FOUND.into_response(),
        Ok(_) => {
            state.relay.disconnect_device(&device.account_id, &id);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => internal(error),
    }
}

/// Deletes the account with its devices, passkeys and synced data.
pub async fn delete_account(
    State(state): State<Shared>,
    Authenticated(device): Authenticated,
) -> Response {
    let deleted = sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(&device.account_id)
        .execute(&state.db)
        .await;
    match deleted {
        Ok(_) => {
            state.relay.disconnect_account(&device.account_id);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => internal(error),
    }
}
