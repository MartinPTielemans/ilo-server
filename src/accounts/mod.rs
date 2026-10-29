//! Accounts: sign-in by mailed code or passkey, and the OpenID Connect
//! provider through which ilo gets its tokens.

pub mod devices;
pub mod oidc;
mod pages;
pub use pages::{script as pages_script, style as pages_style};
pub mod sign_in;

use webauthn_rs::prelude::{Passkey, Uuid};

use crate::db::{self, Db};

/// The address as typed, without the differences that don't make it another mailbox.
pub fn normalize_email(email: &str) -> Option<String> {
    let email = email.trim().to_lowercase();
    let valid = email.len() <= 254 && email.parse::<lettre::Address>().is_ok();
    valid.then_some(email)
}

pub async fn find_by_email(db: &Db, email: &str) -> anyhow::Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT id FROM accounts WHERE email = $1")
            .bind(email)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn find_or_create(db: &Db, email: &str) -> anyhow::Result<String> {
    // A UUID, since a passkey names its user with one.
    let id = Uuid::from_bytes(db::random_bytes::<16>()).to_string();
    sqlx::query("INSERT INTO accounts (id, email, created_at) VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING")
        .bind(&id)
        .bind(email)
        .bind(db::now())
        .execute(db)
        .await?;
    Ok(find_by_email(db, email)
        .await?
        .expect("the account was just made"))
}

pub async fn email(db: &Db, account_id: &str) -> anyhow::Result<String> {
    Ok(
        sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_one(db)
            .await?,
    )
}

pub async fn passkeys(db: &Db, account_id: &str) -> anyhow::Result<Vec<Passkey>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT passkey FROM passkeys WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(account_id)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|row| Ok(serde_json::from_str(row)?))
        .collect()
}
