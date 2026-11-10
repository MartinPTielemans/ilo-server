//! One account's token against another account's ids, on every route that
//! reads or writes stored data: each gets nothing and changes nothing. The
//! server takes the account from the token alone, so an id in a body or path
//! only ever names a row of the token's own account.

// Only the pairing steps a stranger tries are used here.
#[allow(dead_code)]
#[path = "pairing/client.rs"]
mod client;
mod common;

use client::*;
use common::*;
use ilo_server::pb::SyncEntity;
use serde_json::{Value, json};

fn preference(tag: &str, ciphertext: &[u8]) -> SyncEntity {
    SyncEntity {
        id_string: Some(format!("client-{tag}")),
        version: Some(0),
        client_tag_hash: Some(tag.into()),
        specifics: Some(encrypted_specifics(PREFERENCES, ciphertext)),
        ..Default::default()
    }
}

async fn entities(client: &mut Client, data_type: i32) -> Vec<SyncEntity> {
    client
        .get_updates(vec![marker(data_type, None)])
        .await
        .get_updates
        .unwrap()
        .entries
}

async fn api(
    server: &Server,
    method: reqwest::Method,
    path: &str,
    token: &str,
) -> reqwest::Response {
    reqwest::Client::new()
        .request(method, format!("{}{path}", server.url))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

async fn device_ids(server: &Server, token: &str) -> Vec<String> {
    let listed: Value = api(server, reqwest::Method::GET, "/api/devices", token)
        .await
        .json()
        .await
        .unwrap();
    listed["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|device| device["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn a_commit_naming_another_accounts_ids_changes_none_of_its_data() {
    let server = start().await;
    let mut a = server.device(&unique_email("a"), "Mac").await;
    let mut b = server.device(&unique_email("b"), "Mac").await;

    let bar = entities(&mut a, BOOKMARKS)
        .await
        .into_iter()
        .find(|entity| entity.server_defined_unique_tag() == "bookmark_bar")
        .unwrap();
    let folder = SyncEntity {
        id_string: Some("11111111-2222-4333-8444-555555555555".into()),
        parent_id_string: bar.id_string.clone(),
        version: Some(0),
        specifics: Some(encrypted_specifics(BOOKMARKS, b"a's folder")),
        ..Default::default()
    };
    let child = SyncEntity {
        id_string: Some("66666666-7777-4888-8999-000000000000".into()),
        parent_id_string: folder.id_string.clone(),
        version: Some(0),
        specifics: Some(encrypted_specifics(BOOKMARKS, b"a's child")),
        ..Default::default()
    };
    a.commit(vec![folder, child, preference("theme", b"a's secret")])
        .await;
    let a_bookmarks = entities(&mut a, BOOKMARKS).await;
    let a_preferences = entities(&mut a, PREFERENCES).await;
    let a_folder = a_bookmarks
        .iter()
        .find(|entity| entity.specifics() == encrypted_specifics(BOOKMARKS, b"a's folder"))
        .unwrap();
    let a_theme = a_preferences
        .iter()
        .find(|entity| entity.specifics() == encrypted_specifics(PREFERENCES, b"a's secret"))
        .unwrap();

    // B names A's ids as its own: an update under A's client tag, a child, a deletion.
    b.commit(vec![
        SyncEntity {
            id_string: a_theme.id_string.clone(),
            version: a_theme.version,
            client_tag_hash: Some("theme".into()),
            specifics: Some(encrypted_specifics(PREFERENCES, b"b's overwrite")),
            ..Default::default()
        },
        SyncEntity {
            id_string: Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into()),
            parent_id_string: a_folder.id_string.clone(),
            version: Some(0),
            specifics: Some(encrypted_specifics(BOOKMARKS, b"b's child")),
            ..Default::default()
        },
        SyncEntity {
            id_string: a_folder.id_string.clone(),
            version: a_folder.version,
            deleted: Some(true),
            specifics: Some(ilo_server::sync::empty_specifics(BOOKMARKS)),
            ..Default::default()
        },
    ])
    .await;
    assert_eq!(entities(&mut a, BOOKMARKS).await, a_bookmarks);
    assert_eq!(entities(&mut a, PREFERENCES).await, a_preferences);
    for data_type in [BOOKMARKS, PREFERENCES] {
        for entity in entities(&mut b, data_type).await {
            assert!(
                !String::from_utf8_lossy(entity.specifics()).contains("a's"),
                "B sees none of A's data: {entity:?}"
            );
        }
    }
}

#[tokio::test]
async fn clearing_one_accounts_server_data_leaves_anothers() {
    let server = start().await;
    let mut a = server.device(&unique_email("a"), "Mac").await;
    let mut b = server.device(&unique_email("b"), "Mac").await;
    a.commit(vec![preference("theme", b"a's secret")]).await;
    b.commit(vec![preference("theme", b"b's secret")]).await;
    let before = entities(&mut a, PREFERENCES).await;

    b.clear_server_data().await;

    assert_eq!(entities(&mut a, PREFERENCES).await, before);
    assert!(entities(&mut b, PREFERENCES).await.is_empty());
}

#[tokio::test]
async fn another_accounts_devices_cant_be_listed_or_removed_and_deleting_an_account_spares_them() {
    let server = start().await;
    let mut a = server.device(&unique_email("a"), "Mac").await;
    let b = server.device(&unique_email("b"), "Mac").await;
    a.commit(vec![preference("theme", b"a's secret")]).await;
    let a_ids = device_ids(&server, &a.access_token).await;
    let a_device = &a_ids[0];

    assert!(
        !device_ids(&server, &b.access_token)
            .await
            .contains(a_device)
    );
    let removed = api(
        &server,
        reqwest::Method::DELETE,
        &format!("/api/devices/{a_device}"),
        &b.access_token,
    )
    .await;
    assert_eq!(removed.status(), 404);
    let deleted = api(
        &server,
        reqwest::Method::DELETE,
        "/api/account",
        &b.access_token,
    )
    .await;
    assert!(deleted.status().is_success(), "{}", deleted.status());

    assert_eq!(device_ids(&server, &a.access_token).await, a_ids);
    let userinfo = api(&server, reqwest::Method::GET, "/userinfo", &a.access_token).await;
    assert_eq!(userinfo.status(), 200);
    assert_eq!(entities(&mut a, PREFERENCES).await.len(), 1);
}

#[tokio::test]
async fn no_step_of_another_accounts_pairing_answers_or_ends_it() {
    let server = start().await;
    let email = unique_email("a");
    let mut mac = server.device(&email, "Mac").await.relay().await;
    let mut laptop = server.device(&email, "Laptop").await.relay().await;
    let mut stranger = server.device(&unique_email("b"), "Mac").await.relay().await;
    let laptop_keys = KeyPair::generate();
    laptop
        .send(json!({
            "type": "pair_request",
            "commitment": text(&commitment(&laptop_keys.public)),
            "name": "Laptop",
            "os": "macOS",
        }))
        .await;
    let pairing = laptop.next().await["pairing"].as_str().unwrap().to_owned();
    assert_eq!(mac.next().await["pairing"], pairing);

    let key = text(&KeyPair::generate().public);
    for frame in [
        json!({ "type": "pair_accept", "pairing": pairing, "public_key": key }),
        json!({ "type": "pair_reveal", "pairing": pairing, "public_key": key }),
        json!({ "type": "pair_seal", "pairing": pairing, "sealed": "x" }),
        json!({ "type": "pair_cancel", "pairing": pairing }),
    ] {
        stranger.send(frame.clone()).await;
        assert_eq!(
            stranger.next().await["message"],
            "no such pairing",
            "{frame}"
        );
    }

    // The account's own devices still carry it on, having heard nothing of the stranger.
    mac.send(json!({ "type": "pair_accept", "pairing": pairing, "public_key": key }))
        .await;
    let accepted = laptop.next().await;
    assert_eq!(accepted["type"], "pair_accept", "{accepted}");
    assert_eq!(accepted["from"], mac.device);
}
