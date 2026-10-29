//! `/command/`: Chromium's sync protocol, so ilo's engine syncs here instead of to Google.
//!
//! The behaviour follows Chromium's own test server, LoopbackServer
//! (components/sync/test/loopback_server/, BSD), at the engine's commit
//! 1d17a2e2ee147bb7d6ae2ab6abdb3a2510c17775: the same ids, permanent folders,
//! progress tokens and keystore keys. No code is copied from it.
//!
//! Specifics stay bytes. The server reads only their top-level field number,
//! which names the data type even when the rest is encrypted.

use std::collections::{BTreeSet, HashMap};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use prost::Message;
use sqlx::{Any, Transaction};

use crate::Shared;
use crate::db::{self, Db};
use crate::pb::{
    self, SyncEntity, client_to_server_message::Contents, commit_response, sync_enums::ErrorType,
};
use crate::tokens::{Authenticated, Device};

/// Field numbers in EntitySpecifics, which the protocol uses as data type ids.
pub const BOOKMARKS: i32 = 32904;
pub const NIGORI: i32 = 47745;
const ENCRYPTED: u64 = 1;
const MAX_BATCH: usize = 500;
const ROOT_PARENT: &str = "0";
const BOOKMARK_FOLDERS: [(&str, &str); 3] = [
    ("bookmark_bar", "Bookmark Bar"),
    ("other_bookmarks", "Other Bookmarks"),
    ("synced_bookmarks", "Synced Bookmarks"),
];

pub async fn command(
    State(state): State<Shared>,
    Authenticated(device): Authenticated,
    body: Bytes,
) -> Response {
    let Ok(message) = pb::ClientToServerMessage::decode(body) else {
        return (StatusCode::BAD_REQUEST, "not a ClientToServerMessage").into_response();
    };
    match handle(&state.db, &device, message).await {
        Ok(Handled { response, changed }) => {
            if let Some(types) = changed {
                state
                    .relay
                    .notify_changed(&device.account_id, &device.id, &types);
            }
            (
                [(header::CONTENT_TYPE, "application/octet-stream")],
                response.encode_to_vec(),
            )
                .into_response()
        }
        Err(Error::BadRequest(reason)) => (StatusCode::BAD_REQUEST, reason).into_response(),
        Err(Error::Internal(error)) => {
            tracing::error!(%error, "a sync command failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub enum Error {
    BadRequest(&'static str),
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for Error {
    fn from(error: E) -> Self {
        Self::Internal(error.into())
    }
}

pub struct Handled {
    pub response: pb::ClientToServerResponse,
    /// The data types other devices should fetch, when the command changed any.
    /// Empty means all of them.
    pub changed: Option<BTreeSet<i32>>,
}

pub async fn handle(
    db: &Db,
    device: &Device,
    message: pb::ClientToServerMessage,
) -> Result<Handled, Error> {
    let account = device.account_id.as_str();
    let store = ensure_store(db, account).await?;
    let mut response = pb::ClientToServerResponse::default();
    let mut changed = None;
    let sent_birthday = message
        .store_birthday
        .as_deref()
        .filter(|birthday| !birthday.is_empty());
    if sent_birthday.is_some_and(|birthday| birthday != store.birthday) {
        // The data was cleared since this client last synced.
        response.set_error_code(ErrorType::NotMyBirthday);
        response.store_birthday = Some(store.birthday);
        return Ok(Handled { response, changed });
    }
    let mut birthday = store.birthday.clone();
    match Contents::try_from(message.message_contents) {
        Ok(Contents::GetUpdates) => {
            let request = message.get_updates.unwrap_or_default();
            response.get_updates = Some(get_updates(db, account, &store, &request).await?);
        }
        Ok(Contents::Commit) => {
            let request = message.commit.unwrap_or_default();
            let (commit, types) = commit(db, account, &request).await?;
            response.commit = Some(commit);
            changed = (!types.is_empty()).then_some(types);
        }
        Ok(Contents::ClearServerData) => {
            birthday = clear(db, account, &store).await?;
            response.clear_server_data = Some(Default::default());
            changed = Some(BTreeSet::new());
        }
        _ => return Err(Error::BadRequest("unsupported message_contents")),
    }
    response.set_error_code(ErrorType::Success);
    response.store_birthday = Some(birthday);
    Ok(Handled { response, changed })
}

struct Store {
    birthday: String,
    keystore_key: Vec<u8>,
}

async fn read_store(db: &Db, account: &str) -> anyhow::Result<Option<Store>> {
    let row: Option<(String, Vec<u8>)> =
        sqlx::query_as("SELECT birthday, keystore_key FROM sync_stores WHERE account_id = $1")
            .bind(account)
            .fetch_optional(db)
            .await?;
    Ok(row.map(|(birthday, keystore_key)| Store {
        birthday,
        keystore_key,
    }))
}

async fn ensure_store(db: &Db, account: &str) -> anyhow::Result<Store> {
    if let Some(store) = read_store(db, account).await? {
        return Ok(store);
    }
    let mut tx = db.begin().await?;
    let made = sqlx::query(
        "INSERT INTO sync_stores (account_id, birthday, version, keystore_key) VALUES ($1, $2, 0, $3) \
         ON CONFLICT (account_id) DO NOTHING",
    )
    .bind(account)
    .bind(db::now_millis().to_string())
    .bind(db::random_bytes::<16>().to_vec())
    .execute(&mut *tx)
    .await?;
    if made.rows_affected() == 1 {
        add_top_levels(&mut tx, account).await?;
    }
    tx.commit().await?;
    Ok(read_store(db, account)
        .await?
        .expect("the store was just made"))
}

/// The roots that bookmarks hang from and that hold the account's Nigori.
async fn add_top_levels(tx: &mut Transaction<'_, Any>, account: &str) -> anyhow::Result<()> {
    for (data_type, name) in [(BOOKMARKS, "Bookmarks"), (NIGORI, "Nigori")] {
        let tag = root_tag(data_type);
        save_permanent(tx, account, data_type, &tag, name, ROOT_PARENT.into()).await?;
    }
    Ok(())
}

fn root_tag(data_type: i32) -> String {
    match data_type {
        BOOKMARKS => "google_chrome_bookmarks".into(),
        NIGORI => "google_chrome_nigori".into(),
        _ => unreachable!("only bookmarks and Nigori have permanent roots"),
    }
}

fn server_id(data_type: i32, inner: &str) -> String {
    format!("{data_type}_{inner}")
}

async fn save_permanent(
    tx: &mut Transaction<'_, Any>,
    account: &str,
    data_type: i32,
    tag: &str,
    name: &str,
    parent_id: String,
) -> anyhow::Result<()> {
    let entity = SyncEntity {
        id_string: Some(server_id(data_type, tag)),
        parent_id_string: Some(parent_id),
        version: Some(next_version(tx, account).await?),
        name: Some(name.into()),
        server_defined_unique_tag: Some(tag.into()),
        deleted: Some(false),
        specifics: Some(empty_specifics(data_type)),
        ..Default::default()
    };
    save(tx, account, data_type, &entity).await
}

async fn next_version(tx: &mut Transaction<'_, Any>, account: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "UPDATE sync_stores SET version = version + 1 WHERE account_id = $1 RETURNING version",
    )
    .bind(account)
    .fetch_one(&mut **tx)
    .await?)
}

async fn save(
    tx: &mut Transaction<'_, Any>,
    account: &str,
    data_type: i32,
    entity: &SyncEntity,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO sync_entities \
         (account_id, id, data_type, version, parent_id, deleted, client_tag_hash, server_tag, entity) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (account_id, id) DO UPDATE SET data_type = excluded.data_type, \
         version = excluded.version, parent_id = excluded.parent_id, deleted = excluded.deleted, \
         client_tag_hash = excluded.client_tag_hash, server_tag = excluded.server_tag, entity = excluded.entity",
    )
    .bind(account)
    .bind(entity.id_string())
    .bind(data_type as i64)
    .bind(entity.version())
    .bind(entity.parent_id_string.clone())
    .bind(entity.deleted() as i64)
    .bind(entity.client_tag_hash.clone())
    .bind(entity.server_defined_unique_tag.clone())
    .bind(entity.encode_to_vec())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A specifics message with only its data type's field, empty.
pub fn empty_specifics(data_type: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    prost::encoding::encode_key(
        data_type as u32,
        prost::encoding::WireType::LengthDelimited,
        &mut bytes,
    );
    bytes.push(0);
    bytes
}

/// The data type of serialized specifics: their first field other than `encrypted`.
pub fn data_type_of(mut specifics: &[u8]) -> Option<i32> {
    use prost::encoding::{WireType, decode_key, decode_varint};
    while !specifics.is_empty() {
        let (field, wire_type) = decode_key(&mut specifics).ok()?;
        if u64::from(field) != ENCRYPTED {
            return i32::try_from(field).ok();
        }
        let skip = match wire_type {
            WireType::Varint => {
                decode_varint(&mut specifics).ok()?;
                0
            }
            WireType::SixtyFourBit => 8,
            WireType::ThirtyTwoBit => 4,
            WireType::LengthDelimited => {
                usize::try_from(decode_varint(&mut specifics).ok()?).ok()?
            }
            WireType::StartGroup | WireType::EndGroup => return None,
        };
        specifics = specifics.get(skip..)?;
    }
    None
}

fn data_type_of_id(id: &str) -> Option<i32> {
    id.split_once('_')?.0.parse().ok()
}

fn token(version: i64) -> Vec<u8> {
    version.to_string().into_bytes()
}

fn since(token: Option<&[u8]>) -> i64 {
    token
        .and_then(|token| std::str::from_utf8(token).ok()?.parse().ok())
        .unwrap_or(0)
}

async fn get_updates(
    db: &Db,
    account: &str,
    store: &Store,
    request: &pb::GetUpdatesMessage,
) -> anyhow::Result<pb::GetUpdatesResponse> {
    let initial_bookmarks = request
        .from_progress_marker
        .iter()
        .any(|marker| marker.data_type_id() == BOOKMARKS && marker.token().is_empty());
    if initial_bookmarks {
        add_bookmark_folders(db, account).await?;
    }
    // Everything at or below this version is committed, since a commit holds
    // its store row until it ends.
    let snapshot: i64 = sqlx::query_scalar("SELECT version FROM sync_stores WHERE account_id = $1")
        .bind(account)
        .fetch_one(db)
        .await?;
    let mut found: Vec<(i32, i64, Vec<u8>)> = Vec::new();
    let mut wanted = Vec::new();
    for marker in &request.from_progress_marker {
        let data_type = marker.data_type_id();
        let since = since(marker.token.as_deref());
        let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT version, entity FROM sync_entities \
             WHERE account_id = $1 AND data_type = $2 AND version > $3 AND version <= $4 \
             ORDER BY version LIMIT $5",
        )
        .bind(account)
        .bind(data_type as i64)
        .bind(since)
        .bind(snapshot)
        .bind((MAX_BATCH + 1) as i64)
        .fetch_all(db)
        .await?;
        found.extend(
            rows.into_iter()
                .map(|(version, entity)| (data_type, version, entity)),
        );
        wanted.push((data_type, since));
    }
    found.sort_by_key(|(_, version, _)| *version);
    let left_out = found.split_off(found.len().min(MAX_BATCH));

    let mut response = pb::GetUpdatesResponse::default();
    let mut changes_remaining = 0;
    for (data_type, since) in wanted {
        let sent = found
            .iter()
            .filter(|(t, ..)| *t == data_type)
            .map(|(_, version, _)| *version)
            .max();
        let reached = if left_out.iter().any(|(t, ..)| *t == data_type) {
            let reached = sent.unwrap_or(since);
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sync_entities \
                 WHERE account_id = $1 AND data_type = $2 AND version > $3 AND version <= $4",
            )
            .bind(account)
            .bind(data_type as i64)
            .bind(reached)
            .bind(snapshot)
            .fetch_one(db)
            .await?;
            changes_remaining += count;
            reached
        } else {
            snapshot.max(since)
        };
        response
            .new_progress_marker
            .push(pb::DataTypeProgressMarker {
                data_type_id: Some(data_type),
                token: Some(token(reached)),
                ..Default::default()
            });
    }
    for (_, _, entity) in found {
        response
            .entries
            .push(SyncEntity::decode(entity.as_slice())?);
    }
    response.changes_remaining = Some(changes_remaining);
    // The client asks for the keystore key to set up Nigori. With a custom
    // passphrase, which ilo uses, the key encrypts nothing.
    if request.need_encryption_key() {
        response.encryption_keys.push(store.keystore_key.clone());
    }
    Ok(response)
}

async fn add_bookmark_folders(db: &Db, account: &str) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    lock_store(&mut tx, account).await?;
    for (tag, name) in BOOKMARK_FOLDERS {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT version FROM sync_entities WHERE account_id = $1 AND id = $2",
        )
        .bind(account)
        .bind(server_id(BOOKMARKS, tag))
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            let parent = server_id(BOOKMARKS, &root_tag(BOOKMARKS));
            save_permanent(&mut tx, account, BOOKMARKS, tag, name, parent).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

/// Takes the account's store row first, so commits run one at a time and
/// their versions become visible in order.
async fn lock_store(tx: &mut Transaction<'_, Any>, account: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE sync_stores SET version = version WHERE account_id = $1")
        .bind(account)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct Existing {
    version: i64,
    deleted: i64,
    server_tag: Option<String>,
    entity: Vec<u8>,
}

async fn commit(
    db: &Db,
    account: &str,
    request: &pb::CommitMessage,
) -> anyhow::Result<(pb::CommitResponse, BTreeSet<i32>)> {
    let mut tx = db.begin().await?;
    lock_store(&mut tx, account).await?;
    let mut response = pb::CommitResponse::default();
    let mut changed = BTreeSet::new();
    // New items in one commit can name each other by their client ids.
    let mut server_ids = HashMap::new();
    for entry in &request.entries {
        let (result, data_type) = commit_entry(
            &mut tx,
            account,
            request.cache_guid(),
            entry,
            &mut server_ids,
        )
        .await?;
        if let Some(data_type) = data_type {
            changed.insert(data_type);
        }
        response.entryresponse.push(result);
    }
    tx.commit().await?;
    Ok((response, changed))
}

fn refused(kind: commit_response::ResponseType, message: &str) -> commit_response::EntryResponse {
    let mut response = commit_response::EntryResponse {
        error_message: Some(message.into()),
        ..Default::default()
    };
    response.set_response_type(kind);
    response
}

async fn commit_entry(
    tx: &mut Transaction<'_, Any>,
    account: &str,
    cache_guid: &str,
    entry: &SyncEntity,
    server_ids: &mut HashMap<String, String>,
) -> anyhow::Result<(commit_response::EntryResponse, Option<i32>)> {
    use commit_response::ResponseType::{Conflict, InvalidMessage, Success};
    let client_id = entry.id_string();
    let version = entry.version();
    let Some(data_type) = entry
        .specifics
        .as_deref()
        .and_then(data_type_of)
        .or_else(|| data_type_of_id(client_id))
    else {
        return Ok((refused(InvalidMessage, "the entity has no data type"), None));
    };
    if entry.deleted() && data_type == NIGORI {
        // Every store keeps its Nigori; a client resets encryption by
        // clearing the server data instead.
        return Ok((refused(InvalidMessage, "Nigori can't be deleted"), None));
    }
    if entry.deleted() && version == 0 {
        return Ok((
            refused(InvalidMessage, "the server never had this entity"),
            None,
        ));
    }
    let id = if data_type == NIGORI {
        server_id(NIGORI, &root_tag(NIGORI))
    } else if version > 0 {
        client_id.to_owned()
    } else if data_type == BOOKMARKS && !client_id.is_empty() {
        server_id(BOOKMARKS, client_id)
    } else if let Some(tag) = entry
        .client_tag_hash
        .as_deref()
        .filter(|tag| !tag.is_empty())
    {
        server_id(data_type, tag)
    } else {
        return Ok((
            refused(InvalidMessage, "a new entity needs a client tag hash"),
            None,
        ));
    };

    let existing: Option<Existing> =
        sqlx::query_as("SELECT version, deleted, server_tag, entity FROM sync_entities WHERE account_id = $1 AND id = $2")
            .bind(account)
            .bind(&id)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some(existing) = &existing {
        if existing.server_tag.is_some() && data_type != NIGORI {
            return Ok((
                refused(InvalidMessage, "permanent folders can't change"),
                None,
            ));
        }
        let recreating = existing.deleted != 0 && version == 0;
        if existing.version != version && !recreating {
            let mut conflict = refused(Conflict, "the server has a newer version");
            conflict.id_string = Some(id);
            conflict.version = Some(existing.version);
            return Ok((conflict, None));
        }
    }
    let before = existing
        .as_ref()
        .filter(|existing| existing.deleted == 0)
        .map(|existing| SyncEntity::decode(existing.entity.as_slice()))
        .transpose()?;

    let new_version = next_version(tx, account).await?;
    let stored = if entry.deleted() {
        tombstone(&id, data_type, new_version, entry, before.as_ref())
    } else {
        let mut stored = entry.clone();
        stored.id_string = Some(id.clone());
        stored.version = Some(new_version);
        stored.deleted = Some(false);
        stored.server_defined_unique_tag = None;
        if data_type == NIGORI {
            let root = before.as_ref().expect("Nigori is never deleted");
            stored.parent_id_string = root.parent_id_string.clone();
            stored.name = root.name.clone();
            stored.server_defined_unique_tag = root.server_defined_unique_tag.clone();
        } else if data_type == BOOKMARKS {
            let parent = entry.parent_id_string();
            stored.parent_id_string = Some(
                server_ids
                    .get(parent)
                    .cloned()
                    .unwrap_or_else(|| parent.to_owned()),
            );
        }
        match &before {
            Some(before) => {
                stored.originator_cache_guid = before.originator_cache_guid.clone();
                stored.originator_client_item_id = before.originator_client_item_id.clone();
                stored.ctime = before.ctime.or(stored.ctime);
            }
            None => {
                stored.originator_cache_guid = Some(cache_guid.to_owned());
                if data_type == BOOKMARKS {
                    stored.originator_client_item_id = Some(client_id.to_owned());
                }
            }
        }
        stored
    };
    save(tx, account, data_type, &stored).await?;
    if entry.deleted() && data_type == BOOKMARKS {
        delete_children(tx, account, &id, entry).await?;
    }
    if id != client_id {
        server_ids.insert(client_id.to_owned(), id.clone());
    }
    let mut response = commit_response::EntryResponse {
        id_string: Some(id),
        version: Some(new_version),
        ..Default::default()
    };
    response.set_response_type(Success);
    Ok((response, Some(data_type)))
}

/// What's kept of a deleted entity: enough for other clients to delete it too, and no data.
fn tombstone(
    id: &str,
    data_type: i32,
    version: i64,
    deletion: &SyncEntity,
    before: Option<&SyncEntity>,
) -> SyncEntity {
    SyncEntity {
        id_string: Some(id.to_owned()),
        version: Some(version),
        deleted: Some(true),
        specifics: Some(empty_specifics(data_type)),
        client_tag_hash: deletion
            .client_tag_hash
            .clone()
            .or_else(|| before.and_then(|before| before.client_tag_hash.clone())),
        originator_cache_guid: before.and_then(|before| before.originator_cache_guid.clone()),
        originator_client_item_id: before
            .and_then(|before| before.originator_client_item_id.clone()),
        mtime: deletion.mtime,
        ctime: before.and_then(|before| before.ctime),
        deletion_origin: deletion.deletion_origin.clone(),
        ..Default::default()
    }
}

async fn delete_children(
    tx: &mut Transaction<'_, Any>,
    account: &str,
    parent: &str,
    deletion: &SyncEntity,
) -> anyhow::Result<()> {
    let mut parents = vec![parent.to_owned()];
    while let Some(parent) = parents.pop() {
        let children: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT id, entity FROM sync_entities WHERE account_id = $1 AND parent_id = $2 AND deleted = 0",
        )
        .bind(account)
        .bind(&parent)
        .fetch_all(&mut **tx)
        .await?;
        for (id, entity) in children {
            let child = SyncEntity::decode(entity.as_slice())?;
            let version = next_version(tx, account).await?;
            let mut gone = tombstone(&id, BOOKMARKS, version, deletion, Some(&child));
            gone.client_tag_hash = child.client_tag_hash.clone();
            save(tx, account, BOOKMARKS, &gone).await?;
            parents.push(id);
        }
    }
    Ok(())
}

/// Deletes the account's synced data. The new birthday tells every client to start over.
async fn clear(db: &Db, account: &str, store: &Store) -> anyhow::Result<String> {
    let mut tx = db.begin().await?;
    lock_store(&mut tx, account).await?;
    sqlx::query("DELETE FROM sync_entities WHERE account_id = $1")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    let old: i64 = store.birthday.parse().unwrap_or(0);
    let birthday = db::now_millis().max(old + 1).to_string();
    sqlx::query("UPDATE sync_stores SET birthday = $1, keystore_key = $2 WHERE account_id = $3")
        .bind(&birthday)
        .bind(db::random_bytes::<16>().to_vec())
        .bind(account)
        .execute(&mut *tx)
        .await?;
    add_top_levels(&mut tx, account).await?;
    tx.commit().await?;
    Ok(birthday)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_data_type_is_the_first_field_besides_encrypted() {
        assert_eq!(data_type_of(&empty_specifics(BOOKMARKS)), Some(BOOKMARKS));
        // `encrypted` (field 1) with three bytes, then an empty preference.
        let mut encrypted = vec![0x0a, 3, 1, 2, 3];
        encrypted.extend(empty_specifics(37702));
        assert_eq!(data_type_of(&encrypted), Some(37702));
        assert_eq!(data_type_of(&[0x0a, 3, 1, 2, 3]), None);
        assert_eq!(data_type_of(&[0x0a, 9, 1]), None);
    }

    #[test]
    fn progress_tokens_round_trip() {
        assert_eq!(since(Some(&token(42))), 42);
        assert_eq!(since(None), 0);
        assert_eq!(since(Some(b"junk")), 0);
    }
}
