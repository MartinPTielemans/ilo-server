mod common;

use common::*;
use ilo_server::pb::SyncEntity;
use serde_json::json;

fn preference(tag: &str) -> SyncEntity {
    SyncEntity {
        id_string: Some(tag.into()),
        version: Some(0),
        client_tag_hash: Some(tag.into()),
        specifics: Some(encrypted_specifics(PREFERENCES, b"value")),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_commit_tells_the_accounts_other_devices_what_changed() {
    let server = start().await;
    let email = unique_email("changed");
    let mut mac = server.device(&email, "Mac").await;
    let laptop = server.device(&email, "Laptop").await;
    let stranger = server.device(&unique_email("stranger"), "Mac").await;
    let mut mac_relay = mac.relay().await;
    let mut laptop_relay = laptop.relay().await;
    let mut stranger_relay = stranger.relay().await;

    mac.commit(vec![preference("theme")]).await;
    assert_eq!(
        laptop_relay.next().await,
        json!({ "type": "changed", "types": [PREFERENCES] })
    );

    // A note would be queued ahead of these replies, so none came.
    for relay in [&mut mac_relay, &mut stranger_relay] {
        relay
            .send(json!({ "type": "send", "to": "nobody", "payload": "x", "id": 1 }))
            .await;
        assert_eq!(
            relay.next().await,
            json!({ "type": "undelivered", "to": "nobody", "id": 1 })
        );
    }
}

#[tokio::test]
async fn the_relay_carries_opaque_messages_between_an_accounts_devices() {
    let server = start().await;
    let email = unique_email("messages");
    let mac = server.device(&email, "Mac").await;
    let laptop = server.device(&email, "Laptop").await;
    let stranger = server.device(&unique_email("other"), "Mac").await;
    let mut mac_relay = mac.relay().await;
    let mut laptop_relay = laptop.relay().await;
    let mut stranger_relay = stranger.relay().await;

    mac_relay
        .send(json!({ "type": "send", "to": laptop_relay.device, "payload": "c2VhbGVk" }))
        .await;
    assert_eq!(
        laptop_relay.next().await,
        json!({ "type": "message", "from": mac_relay.device, "payload": "c2VhbGVk" })
    );

    // Another account's device is unreachable, as if offline.
    stranger_relay
        .send(json!({ "type": "send", "to": laptop_relay.device, "payload": "x", "id": "a" }))
        .await;
    assert_eq!(stranger_relay.next().await["type"], "undelivered");
}

#[tokio::test]
async fn removing_a_device_closes_its_connection_and_ends_its_tokens() {
    let server = start().await;
    let email = unique_email("remove");
    let mac = server.device(&email, "Mac").await;
    let laptop = server.device(&email, "Laptop").await;
    let mut laptop_relay = laptop.relay().await;

    let removed = reqwest::Client::new()
        .delete(format!(
            "{}/api/devices/{}",
            server.url, laptop_relay.device
        ))
        .bearer_auth(&mac.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 204);
    assert_eq!(close_code(&laptop_relay.frame().await), Some(4001));
    let status = reqwest::Client::new()
        .get(format!("{}/userinfo", server.url))
        .bearer_auth(&laptop.access_token)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 401);
}

#[tokio::test]
async fn deleting_the_account_signs_every_device_out() {
    let server = start().await;
    let email = unique_email("delete-account");
    let mac = server.device(&email, "Mac").await;
    let laptop = server.device(&email, "Laptop").await;
    let mut laptop_relay = laptop.relay().await;
    let deleted = reqwest::Client::new()
        .delete(format!("{}/api/account", server.url))
        .bearer_auth(&mac.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 204);
    assert_eq!(close_code(&laptop_relay.frame().await), Some(4001));
    for token in [&mac.access_token, &laptop.access_token] {
        let status = reqwest::Client::new()
            .get(format!("{}/userinfo", server.url))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 401);
    }
}

#[tokio::test]
async fn the_relay_needs_a_device_token() {
    let server = start().await;
    let url = server.url.replace("http://", "ws://") + "/relay";
    let error = tokio_tungstenite::connect_async(url).await.unwrap_err();
    assert!(error.to_string().contains("401"), "{error}");
}
