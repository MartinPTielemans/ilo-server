//! The database: SQLite in a file, or Postgres, through one set of queries.
//!
//! Queries use `$1` parameters, `ON CONFLICT` and `RETURNING`, which both
//! backends understand. Flags are integers and times are Unix seconds, since
//! sqlx's `Any` driver carries no shared boolean or time type.

use anyhow::Context;
use base64::Engine;
use sqlx::any::{AnyPoolOptions, install_default_drivers};
use sqlx::{AnyPool, Executor};

pub type Db = AnyPool;

static SQLITE: sqlx::migrate::Migrator = sqlx::migrate!("migrations/sqlite");
static POSTGRES: sqlx::migrate::Migrator = sqlx::migrate!("migrations/postgres");

pub async fn connect(url: &str) -> anyhow::Result<Db> {
    install_default_drivers();
    let sqlite = url.starts_with("sqlite:");
    let pool = AnyPoolOptions::new()
        .max_connections(if sqlite { 4 } else { 10 })
        .after_connect(move |connection, _| {
            Box::pin(async move {
                if sqlite {
                    // Readers don't wait on the writer, and the writer waits
                    // for another instead of failing.
                    connection.execute("PRAGMA journal_mode = WAL").await?;
                    connection.execute("PRAGMA busy_timeout = 5000").await?;
                    connection.execute("PRAGMA foreign_keys = ON").await?;
                }
                Ok(())
            })
        })
        .connect(url)
        .await
        .with_context(|| format!("can't open the database at {}", redact(url)))?;
    let migrator = if sqlite { &SQLITE } else { &POSTGRES };
    migrator
        .run(&pool)
        .await
        .context("can't migrate the database")?;
    Ok(pool)
}

fn redact(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) if parsed.password().is_some() => {
            let _ = parsed.set_password(Some("…"));
            parsed.to_string()
        }
        _ => url.to_owned(),
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    openssl::rand::rand_bytes(&mut bytes).expect("the system's random source failed");
    bytes
}

/// A random identifier that's safe in URLs, cookies and logs.
pub fn random_id() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<16>())
}

/// How secrets (codes and tokens) are stored, so a copy of the database can't sign in.
pub fn hash(secret: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(openssl::sha::sha256(secret.as_bytes()))
}
