mod common;

use common::*;
use ilo_server::pb::{self, SyncEntity, commit_response::ResponseType, sync_enums::ErrorType};

fn preference(tag: &str, version: i64, ciphertext: &[u8]) -> SyncEntity {
    SyncEntity {
        id_string: Some(format!("client-{tag}")),
        version: Some(version),
        client_tag_hash: Some(tag.into()),
        specifics: Some(encrypted_specifics(PREFERENCES, ciphertext)),
        ..Default::default()
    }
}

fn token_for(response: &pb::ClientToServerResponse, data_type: i32) -> Vec<u8> {
    let updates = response.get_updates.as_ref().unwrap();
    updates
        .new_progress_marker
        .iter()
        .find(|marker| marker.data_type_id() == data_type)
        .unwrap()
        .token()
        .to_vec()
}

#[tokio::test]
async fn a_commit_from_one_device_shows_up_in_anothers_get_updates() {
    let server = start().await;
    let email = unique_email("sync");
    let mut mac = server.device(&email, "Mac").await;
    let mut laptop = server.device(&email, "Laptop").await;

    let first = mac
        .get_updates(vec![
            marker(BOOKMARKS, None),
            marker(NIGORI, None),
            marker(PREFERENCES, None),
        ])
        .await;
    assert_eq!(first.error_code(), ErrorType::Success);
    let updates = first.get_updates.as_ref().unwrap();
    assert_eq!(
        updates.encryption_keys.len(),
        1,
        "the keystore key Nigori asks for"
    );
    let tags: Vec<_> = updates
        .entries
        .iter()
        .filter_map(|entity| entity.server_defined_unique_tag.as_deref())
        .collect();
    for tag in [
        "google_chrome_bookmarks",
        "google_chrome_nigori",
        "bookmark_bar",
        "other_bookmarks",
        "synced_bookmarks",
    ] {
        assert!(tags.contains(&tag), "{tag} is missing from {tags:?}");
    }
    let bar = updates
        .entries
        .iter()
        .find(|entity| entity.server_defined_unique_tag() == "bookmark_bar")
        .unwrap();

    // A folder and a bookmark in it, the bookmark naming the folder by its client id.
    let folder_id = "6f1d1e4c-0b7a-4b8e-9a51-6c0a6f2b5d10";
    let bookmark_id = "0c9f8a7e-3d2b-4c1a-8e5f-9a8b7c6d5e4f";
    let folder = SyncEntity {
        id_string: Some(folder_id.into()),
        parent_id_string: Some(bar.id_string().into()),
        version: Some(0),
        folder: Some(true),
        specifics: Some(encrypted_specifics(BOOKMARKS, b"folder")),
        ..Default::default()
    };
    let bookmark = SyncEntity {
        id_string: Some(bookmark_id.into()),
        parent_id_string: Some(folder_id.into()),
        version: Some(0),
        specifics: Some(encrypted_specifics(BOOKMARKS, b"bookmark")),
        ..Default::default()
    };
    let committed = mac
        .commit(vec![preference("theme", 0, b"dark"), folder, bookmark])
        .await;
    let results = &committed.commit.as_ref().unwrap().entryresponse;
    assert!(
        results
            .iter()
            .all(|result| result.response_type() == ResponseType::Success),
        "{results:?}"
    );
    let folder_server_id = results[1].id_string().to_owned();

    let seen = laptop
        .get_updates(vec![marker(BOOKMARKS, None), marker(PREFERENCES, None)])
        .await;
    let entries = &seen.get_updates.as_ref().unwrap().entries;
    let theme = entries
        .iter()
        .find(|entity| entity.client_tag_hash() == "theme")
        .unwrap();
    assert_eq!(
        theme.specifics(),
        encrypted_specifics(PREFERENCES, b"dark"),
        "the specifics come back byte for byte"
    );
    assert_eq!(theme.originator_cache_guid(), mac.cache_guid);
    let bookmark = entries
        .iter()
        .find(|entity| entity.originator_client_item_id() == bookmark_id)
        .unwrap();
    assert_eq!(
        bookmark.parent_id_string(),
        folder_server_id,
        "the parent is the folder's server id"
    );

    // The next fetch from the laptop's tokens has only what changed since.
    let since = token_for(&seen, PREFERENCES);
    let updated = mac
        .commit(vec![preference("theme", results[0].version(), b"light")])
        .await;
    let updated_version = updated.commit.unwrap().entryresponse[0].version();
    let next = laptop
        .get_updates(vec![marker(PREFERENCES, Some(since.clone()))])
        .await;
    let entries = &next.get_updates.as_ref().unwrap().entries;
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].specifics(),
        encrypted_specifics(PREFERENCES, b"light")
    );
    assert_eq!(entries[0].version(), updated_version);

    // The laptop's stale write is a conflict, not a lost update.
    let stale = laptop
        .commit(vec![preference("theme", results[0].version(), b"stale")])
        .await;
    assert_eq!(
        stale.commit.unwrap().entryresponse[0].response_type(),
        ResponseType::Conflict
    );
}

#[tokio::test]
async fn another_account_sees_none_of_it() {
    let server = start().await;
    let mut mine = server.device(&unique_email("mine"), "Mac").await;
    let mut theirs = server.device(&unique_email("theirs"), "Mac").await;
    mine.commit(vec![preference("private", 0, b"secret")]).await;
    let seen = theirs.get_updates(vec![marker(PREFERENCES, None)]).await;
    assert!(seen.get_updates.unwrap().entries.is_empty());
}

#[tokio::test]
async fn deleting_a_folder_deletes_what_it_holds() {
    let server = start().await;
    let email = unique_email("delete");
    let mut mac = server.device(&email, "Mac").await;
    let first = mac.get_updates(vec![marker(BOOKMARKS, None)]).await;
    let bar = first
        .get_updates
        .unwrap()
        .entries
        .into_iter()
        .find(|e| e.server_defined_unique_tag() == "bookmark_bar")
        .unwrap();
    let folder = SyncEntity {
        id_string: Some("11111111-2222-4333-8444-555555555555".into()),
        parent_id_string: bar.id_string.clone(),
        version: Some(0),
        specifics: Some(encrypted_specifics(BOOKMARKS, b"folder")),
        ..Default::default()
    };
    let child = SyncEntity {
        id_string: Some("66666666-7777-4888-8999-000000000000".into()),
        parent_id_string: folder.id_string.clone(),
        version: Some(0),
        specifics: Some(encrypted_specifics(BOOKMARKS, b"child")),
        ..Default::default()
    };
    let made = mac
        .commit(vec![folder, child])
        .await
        .commit
        .unwrap()
        .entryresponse;
    let deletion = SyncEntity {
        id_string: Some(made[0].id_string().into()),
        version: Some(made[0].version()),
        deleted: Some(true),
        specifics: Some(ilo_server::sync::empty_specifics(BOOKMARKS)),
        ..Default::default()
    };
    mac.commit(vec![deletion]).await;

    let mut laptop = server.device(&email, "Laptop").await;
    let seen = laptop
        .get_updates(vec![marker(BOOKMARKS, None)])
        .await
        .get_updates
        .unwrap()
        .entries;
    for id in [made[0].id_string(), made[1].id_string()] {
        let entity = seen.iter().find(|entity| entity.id_string() == id).unwrap();
        assert!(entity.deleted(), "{id} should be a tombstone");
        assert_eq!(
            entity.specifics(),
            ilo_server::sync::empty_specifics(BOOKMARKS),
            "a tombstone keeps no data"
        );
    }
}

#[tokio::test]
async fn clearing_the_server_data_starts_every_device_over() {
    let server = start().await;
    let email = unique_email("clear");
    let mut mac = server.device(&email, "Mac").await;
    let mut laptop = server.device(&email, "Laptop").await;
    mac.commit(vec![preference("theme", 0, b"dark")]).await;
    laptop.get_updates(vec![marker(PREFERENCES, None)]).await;
    let old_birthday = laptop.birthday.clone().unwrap();

    let cleared = mac.clear_server_data().await;
    assert_eq!(cleared.error_code(), ErrorType::Success);
    assert_ne!(cleared.store_birthday(), old_birthday);

    let refused = laptop.get_updates(vec![marker(PREFERENCES, None)]).await;
    assert_eq!(refused.error_code(), ErrorType::NotMyBirthday);
    laptop.birthday = None;
    let fresh = laptop.get_updates(vec![marker(PREFERENCES, None)]).await;
    assert!(fresh.get_updates.unwrap().entries.is_empty());
}

#[tokio::test]
async fn sync_needs_a_device_token() {
    let server = start().await;
    let response = reqwest::Client::new()
        .post(format!("{}/command/", server.url))
        .bearer_auth("ilo_at_made-up")
        .body(Vec::new())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn a_long_history_comes_in_batches() {
    let server = start().await;
    let email = unique_email("batches");
    let mut mac = server.device(&email, "Mac").await;
    for batch in 0..11 {
        let entries = (0..50)
            .map(|n| preference(&format!("p{batch}-{n}"), 0, b"x"))
            .collect();
        mac.commit(entries).await;
    }
    let mut laptop = server.device(&email, "Laptop").await;
    let mut token = None;
    let mut seen = 0;
    let mut rounds = 0;
    loop {
        let response = laptop
            .get_updates(vec![marker(PREFERENCES, token.clone())])
            .await;
        let updates = response.get_updates.as_ref().unwrap();
        seen += updates.entries.len();
        rounds += 1;
        token = Some(token_for(&response, PREFERENCES));
        if updates.changes_remaining() == 0 {
            break;
        }
        assert_eq!(updates.changes_remaining() as usize, 550 - seen);
    }
    assert_eq!((seen, rounds), (550, 2));
}
