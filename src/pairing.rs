//! Pairing: a new device gets the account's passphrase from one that has it,
//! through the relay. The server keeps the steps in order and inside the
//! account; the commitment, the keys and the sealed passphrase are opaque to
//! it. `docs/protocol.md` describes the protocol and why each step is there.
//!
//! 1. The new device sends `pair_request` with a commitment to its key, and
//!    the account's other devices get it.
//! 2. One of them sends `pair_accept` with its key, and the request closes
//!    on the rest.
//! 3. The new device sends `pair_reveal` with its key; both now show the
//!    match code.
//! 4. If the codes match, the approver sends `pair_seal`.
//!
//! Either side may send `pair_cancel`. A pairing that can't reach the other
//! side ends, and so does one past its five minutes.

use serde_json::{Value, json};
use sqlx::FromRow;

use crate::Shared;
use crate::db;
use crate::tokens::Device;

pub const LIFETIME: i64 = 5 * 60;
/// Requests an account may make in an hour, so a stolen session can't keep
/// putting requests on the user's other screens.
pub const REQUESTS_PER_HOUR: i64 = 10;
const HOUR: i64 = 60 * 60;
const MAX_KEY: usize = 64;
const MAX_NAME: usize = 100;
const MAX_OS: usize = 50;
const MAX_SEALED: usize = 2048;

#[derive(FromRow)]
struct Pairing {
    id: String,
    account_id: String,
    requester: String,
    approver: Option<String>,
    step: String,
    expires_at: i64,
}

fn error(pairing: Option<&str>, message: &str) -> Option<Value> {
    Some(json!({ "type": "error", "message": message, "pairing": pairing }))
}

fn closed(pairing: &str, reason: &str) -> String {
    json!({ "type": "pair_closed", "pairing": pairing, "reason": reason }).to_string()
}

/// The open requests the account's other devices haven't answered, for a
/// device that has just connected.
pub async fn pending(state: &Shared, device: &Device) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT request FROM pairings WHERE account_id = $1 AND step = 'requested' \
         AND requester <> $2 AND expires_at > $3 ORDER BY created_at",
    )
    .bind(&device.account_id)
    .bind(&device.id)
    .bind(db::now())
    .fetch_all(&state.db)
    .await?)
}

pub async fn request(
    state: &Shared,
    device: &Device,
    commitment: &str,
    name: &str,
    os: &str,
) -> anyhow::Result<Option<Value>> {
    if commitment.len() > MAX_KEY || name.chars().count() > MAX_NAME || os.chars().count() > MAX_OS
    {
        return Ok(error(None, "pairing request too large"));
    }
    let now = db::now();
    // Sweeping here keeps an idle server idle.
    sqlx::query("DELETE FROM pairings WHERE created_at < $1")
        .bind(now - HOUR)
        .execute(&state.db)
        .await?;
    // A device asks once at a time; asking again replaces its request.
    let open: Vec<Pairing> = sqlx::query_as(
        "SELECT id, account_id, requester, approver, step, expires_at FROM pairings \
         WHERE requester = $1 AND step <> 'closed'",
    )
    .bind(&device.id)
    .fetch_all(&state.db)
    .await?;
    for pairing in open {
        close(state, &pairing, &device.id, "cancelled").await?;
    }
    let made: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pairings WHERE account_id = $1 AND created_at > $2",
    )
    .bind(&device.account_id)
    .bind(now - HOUR)
    .fetch_one(&state.db)
    .await?;
    if made >= REQUESTS_PER_HOUR {
        return Ok(error(None, "too many pairing requests; try again later"));
    }
    let id = db::random_id();
    let expires_at = now + LIFETIME;
    let frame = json!({
        "type": "pair_request",
        "pairing": id,
        "from": device.id,
        "name": name,
        "os": os,
        "commitment": commitment,
        "expires_at": expires_at,
    })
    .to_string();
    sqlx::query(
        "INSERT INTO pairings (id, account_id, requester, step, request, created_at, expires_at) \
         VALUES ($1, $2, $3, 'requested', $4, $5, $6)",
    )
    .bind(&id)
    .bind(&device.account_id)
    .bind(&device.id)
    .bind(&frame)
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    state
        .relay
        .broadcast(&device.account_id, &[&device.id], &frame);
    Ok(Some(
        json!({ "type": "pair_requested", "pairing": id, "expires_at": expires_at }),
    ))
}

/// The account's open pairing, or the error to answer with. One past its
/// time closes here, since no timer watches it.
async fn open(state: &Shared, device: &Device, id: &str) -> anyhow::Result<Result<Pairing, Value>> {
    let pairing: Option<Pairing> = sqlx::query_as(
        "SELECT id, account_id, requester, approver, step, expires_at FROM pairings \
         WHERE id = $1 AND account_id = $2 AND step <> 'closed'",
    )
    .bind(id)
    .bind(&device.account_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(pairing) = pairing else {
        return Ok(Err(error(Some(id), "no such pairing").unwrap()));
    };
    if pairing.expires_at <= db::now() {
        close(state, &pairing, &device.id, "expired").await?;
        return Ok(Err(error(Some(id), "this pairing has expired").unwrap()));
    }
    Ok(Ok(pairing))
}

/// Moves the pairing on from `from` to `to`, unless another frame got there first.
async fn advance(
    state: &Shared,
    pairing: &Pairing,
    from: &str,
    to: &str,
    approver: &str,
) -> anyhow::Result<bool> {
    let moved = sqlx::query(
        "UPDATE pairings SET step = $1, approver = $2, request = NULL WHERE id = $3 AND step = $4",
    )
    .bind(to)
    .bind(approver)
    .bind(&pairing.id)
    .bind(from)
    .execute(&state.db)
    .await?;
    Ok(moved.rows_affected() == 1)
}

/// Ends the pairing and tells whoever is still in it, but `by`: while it's
/// a request, every other device of the account; after, the other side.
async fn close(state: &Shared, pairing: &Pairing, by: &str, reason: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE pairings SET step = 'closed', request = NULL WHERE id = $1")
        .bind(&pairing.id)
        .execute(&state.db)
        .await?;
    let frame = closed(&pairing.id, reason);
    if pairing.step == "requested" {
        state.relay.broadcast(&pairing.account_id, &[by], &frame);
    } else {
        for side in [Some(&pairing.requester), pairing.approver.as_ref()]
            .into_iter()
            .flatten()
            .filter(|side| *side != by)
        {
            state
                .relay
                .send_to(&pairing.account_id, side, frame.clone());
        }
    }
    Ok(())
}

/// Passes `frame` to the other side, or ends the pairing when it can't.
async fn pass(
    state: &Shared,
    pairing: &Pairing,
    by: &Device,
    to: &str,
    frame: Value,
) -> anyhow::Result<Option<Value>> {
    if state
        .relay
        .send_to(&pairing.account_id, to, frame.to_string())
    {
        return Ok(None);
    }
    close(state, pairing, &by.id, "unreachable").await?;
    Ok(Some(serde_json::from_str(&closed(
        &pairing.id,
        "unreachable",
    ))?))
}

pub async fn accept(
    state: &Shared,
    device: &Device,
    id: &str,
    public_key: &str,
) -> anyhow::Result<Option<Value>> {
    if public_key.len() > MAX_KEY {
        return Ok(error(Some(id), "key too large"));
    }
    let pairing = match open(state, device, id).await? {
        Ok(pairing) => pairing,
        Err(refused) => return Ok(Some(refused)),
    };
    if pairing.requester == device.id
        || !advance(state, &pairing, "requested", "accepted", &device.id).await?
    {
        return Ok(error(Some(id), "this pairing can't be accepted"));
    }
    state.relay.broadcast(
        &pairing.account_id,
        &[&pairing.requester, &device.id],
        &closed(id, "taken"),
    );
    let pairing = Pairing {
        step: "accepted".into(),
        approver: Some(device.id.clone()),
        ..pairing
    };
    let frame = json!({ "type": "pair_accept", "pairing": id, "from": device.id, "public_key": public_key });
    let requester = pairing.requester.clone();
    pass(state, &pairing, device, &requester, frame).await
}

pub async fn reveal(
    state: &Shared,
    device: &Device,
    id: &str,
    public_key: &str,
) -> anyhow::Result<Option<Value>> {
    if public_key.len() > MAX_KEY {
        return Ok(error(Some(id), "key too large"));
    }
    let pairing = match open(state, device, id).await? {
        Ok(pairing) => pairing,
        Err(refused) => return Ok(Some(refused)),
    };
    let Some(approver) = pairing.approver.clone() else {
        return Ok(error(Some(id), "this pairing hasn't been accepted"));
    };
    if pairing.requester != device.id
        || !advance(state, &pairing, "accepted", "revealed", &approver).await?
    {
        return Ok(error(Some(id), "this pairing can't be revealed"));
    }
    let frame = json!({ "type": "pair_reveal", "pairing": id, "public_key": public_key });
    pass(state, &pairing, device, &approver, frame).await
}

pub async fn seal(
    state: &Shared,
    device: &Device,
    id: &str,
    sealed: &str,
) -> anyhow::Result<Option<Value>> {
    if sealed.len() > MAX_SEALED {
        return Ok(error(Some(id), "sealed passphrase too large"));
    }
    let pairing = match open(state, device, id).await? {
        Ok(pairing) => pairing,
        Err(refused) => return Ok(Some(refused)),
    };
    if pairing.approver.as_deref() != Some(&device.id)
        || !advance(state, &pairing, "revealed", "closed", &device.id).await?
    {
        return Ok(error(Some(id), "this pairing can't be sealed"));
    }
    let frame =
        json!({ "type": "pair_sealed", "pairing": id, "from": device.id, "sealed": sealed });
    if state
        .relay
        .send_to(&pairing.account_id, &pairing.requester, frame.to_string())
    {
        Ok(Some(serde_json::from_str(&closed(id, "done"))?))
    } else {
        Ok(Some(serde_json::from_str(&closed(id, "unreachable"))?))
    }
}

/// The new device giving up, the approver finding the codes differ, or
/// another device declining a request it doesn't recognise.
pub async fn cancel(state: &Shared, device: &Device, id: &str) -> anyhow::Result<Option<Value>> {
    let pairing = match open(state, device, id).await? {
        Ok(pairing) => pairing,
        Err(refused) => return Ok(Some(refused)),
    };
    let party = pairing.requester == device.id || pairing.approver.as_deref() == Some(&device.id);
    if pairing.step != "requested" && !party {
        return Ok(error(Some(id), "this pairing isn't yours to cancel"));
    }
    close(state, &pairing, &device.id, "cancelled").await?;
    Ok(None)
}
