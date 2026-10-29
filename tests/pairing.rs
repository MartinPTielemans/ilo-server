#[path = "pairing/client.rs"]
mod client;
mod common;

use client::*;
use common::*;
use serde_json::{Value, json};

fn pair_request(keys: &KeyPair) -> Value {
    json!({
        "type": "pair_request",
        "commitment": text(&commitment(&keys.public)),
        "name": "Laptop",
        "os": "macOS",
    })
}

async fn requested(relay: &mut Relay, keys: &KeyPair) -> String {
    relay.send(pair_request(keys)).await;
    let reply = relay.next().await;
    assert_eq!(reply["type"], "pair_requested", "{reply}");
    reply["pairing"].as_str().unwrap().to_owned()
}

/// Nothing is queued for the relay: an answer it asks for comes next.
async fn assert_quiet(relay: &mut Relay) {
    relay
        .send(json!({ "type": "send", "to": "nobody", "payload": "x", "id": "quiet" }))
        .await;
    assert_eq!(
        relay.next().await,
        json!({ "type": "undelivered", "to": "nobody", "id": "quiet" })
    );
}

#[tokio::test]
async fn a_new_device_gets_the_secret_from_another_once_their_codes_match() {
    let server = start().await;
    let email = unique_email("pair");
    let mut mac = server.device(&email, "Mac").await.relay().await;
    let mut laptop = server.device(&email, "Laptop").await.relay().await;
    let secret: Key = ilo_server::db::random_bytes::<32>();

    // The laptop has no secret: it asks, committing to a key it keeps back.
    let laptop_keys = KeyPair::generate();
    let pairing = requested(&mut laptop, &laptop_keys).await;

    let request = mac.next().await;
    assert_eq!(request["type"], "pair_request");
    assert_eq!(request["pairing"], pairing);
    assert_eq!(request["from"], laptop.device);
    assert_eq!(
        (&request["name"], &request["os"]),
        (&json!("Laptop"), &json!("macOS"))
    );
    let mac_keys = KeyPair::generate();
    mac.send(
        json!({ "type": "pair_accept", "pairing": pairing, "public_key": text(&mac_keys.public) }),
    )
    .await;

    let accepted = laptop.next().await;
    assert_eq!(accepted["type"], "pair_accept");
    assert_eq!(accepted["from"], mac.device);
    let approver = key(accepted["public_key"].as_str().unwrap()).unwrap();
    laptop
        .send(json!({ "type": "pair_reveal", "pairing": pairing, "public_key": text(&laptop_keys.public) }))
        .await;

    let revealed = mac.next().await;
    assert_eq!(revealed["type"], "pair_reveal");
    let requester = key(revealed["public_key"].as_str().unwrap()).unwrap();
    assert_eq!(
        text(&commitment(&requester)),
        request["commitment"],
        "the revealed key is the one committed to"
    );
    let on_mac = match_code(&requester, &mac_keys.public);
    let on_laptop = match_code(&laptop_keys.public, &approver);
    assert_eq!(on_mac, on_laptop);
    assert_eq!(on_mac.len(), 6);

    // The user saw the same code on both, so the Mac seals the secret.
    let sealed = seal(&mac_keys, &requester, &pairing, &secret).unwrap();
    mac.send(json!({ "type": "pair_seal", "pairing": pairing, "sealed": text(&sealed) }))
        .await;
    assert_eq!(
        mac.next().await,
        json!({ "type": "pair_closed", "pairing": pairing, "reason": "done" })
    );
    let delivered = laptop.next().await;
    assert_eq!(delivered["type"], "pair_sealed");
    assert_eq!(delivered["from"], mac.device);
    let sealed = bytes(delivered["sealed"].as_str().unwrap()).unwrap();
    assert_eq!(
        open(&laptop_keys, &approver, &pairing, &sealed),
        Some(secret)
    );

    // It's over: the server keeps no step of it to replay.
    mac.send(json!({ "type": "pair_seal", "pairing": pairing, "sealed": "x" }))
        .await;
    assert_eq!(mac.next().await["message"], "no such pairing");
}

#[test]
fn a_key_swapped_in_the_middle_breaks_the_commitment_or_the_code() {
    let laptop = KeyPair::generate();
    let mac = KeyPair::generate();
    let server = KeyPair::generate();
    let secret = [7; 32];

    // Revealing another key than the one committed to fails the Mac's check.
    assert_ne!(commitment(&server.public), commitment(&laptop.public));
    // Committing to its own key instead, the server had to choose it before
    // it saw the Mac's, so the codes differ but for one time in a million.
    let impostor = KeyPair::generate();
    assert_ne!(
        match_code(&server.public, &mac.public),
        match_code(&laptop.public, &impostor.public)
    );

    let sealed = seal(&mac, &laptop.public, "p1", &secret).unwrap();
    assert_eq!(open(&laptop, &mac.public, "p1", &sealed), Some(secret));
    assert_eq!(open(&laptop, &server.public, "p1", &sealed), None);
    assert_eq!(open(&server, &mac.public, "p1", &sealed), None);
    assert_eq!(open(&laptop, &mac.public, "p2", &sealed), None);
    // A low-order key would make a shared secret anyone can compute.
    assert_eq!(seal(&mac, &[0; 32], "p1", &secret), None);
}

/// The example in `docs/protocol.md`, worked out separately with Python's
/// `cryptography`, so an implementation can check each step against it.
#[test]
fn every_step_gives_the_protocols_example() {
    let requester = KeyPair::from_private(&[0x11; 32]);
    let approver = KeyPair::from_private(&[0x22; 32]);
    assert_eq!(
        text(&requester.public),
        "e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM"
    );
    assert_eq!(
        text(&approver.public),
        "D6poTtKIZ7l_Smot7l34zpdOdrcBjj8iocTPJnhXDyA"
    );
    assert_eq!(
        text(&commitment(&requester.public)),
        "iQWWm0uPaU4SyelWA0dwWNlsMHC39SNJ4PjHEuJhCMo"
    );
    assert_eq!(match_code(&requester.public, &approver.public), "312568");
    let sealed = seal(&approver, &requester.public, "example", &[0x33; 32]).unwrap();
    assert_eq!(
        text(&sealed),
        "MIbD9AQ11WmirOWxkJoDGTitoTFomGYAyLFIQ20_tWtXiV2OFNqWo46897wVJd9I"
    );
    assert_eq!(
        open(&requester, &approver.public, "example", &sealed),
        Some([0x33; 32])
    );
}

#[tokio::test]
async fn requests_reach_only_the_accounts_devices_and_one_that_connects_later() {
    let server = start().await;
    let email = unique_email("reach");
    let mut mac = server.device(&email, "Mac").await.relay().await;
    let mut laptop = server.device(&email, "Laptop").await.relay().await;
    let phone = server.device(&email, "Phone").await;
    let mut stranger = server
        .device(&unique_email("stranger"), "Mac")
        .await
        .relay()
        .await;

    let pairing = requested(&mut laptop, &KeyPair::generate()).await;
    assert_eq!(mac.next().await["pairing"], pairing);
    assert_quiet(&mut stranger).await;

    let mut phone = phone.relay().await;
    let pending = phone.next().await;
    assert_eq!(pending["type"], "pair_request");
    assert_eq!(pending["pairing"], pairing);

    // Another account can't answer it, and once one device has, the others' prompts close.
    stranger
        .send(json!({ "type": "pair_accept", "pairing": pairing, "public_key": "k" }))
        .await;
    assert_eq!(stranger.next().await["message"], "no such pairing");
    mac.send(json!({ "type": "pair_accept", "pairing": pairing, "public_key": "k" }))
        .await;
    assert_eq!(
        phone.next().await,
        json!({ "type": "pair_closed", "pairing": pairing, "reason": "taken" })
    );
    assert_eq!(laptop.next().await["type"], "pair_accept");
    phone
        .send(json!({ "type": "pair_accept", "pairing": pairing, "public_key": "k" }))
        .await;
    assert_eq!(
        phone.next().await["message"],
        "this pairing can't be accepted"
    );
}

#[tokio::test]
async fn each_step_comes_in_order_from_its_own_device() {
    let server = start().await;
    let email = unique_email("order");
    let mut mac = server.device(&email, "Mac").await.relay().await;
    let mut laptop = server.device(&email, "Laptop").await.relay().await;
    let pairing = requested(&mut laptop, &KeyPair::generate()).await;
    mac.next().await;

    let step =
        |kind: &str| json!({ "type": kind, "pairing": pairing, "public_key": "k", "sealed": "s" });
    laptop.send(step("pair_accept")).await;
    assert_eq!(
        laptop.next().await["message"],
        "this pairing can't be accepted"
    );
    laptop.send(step("pair_reveal")).await;
    assert_eq!(
        laptop.next().await["message"],
        "this pairing hasn't been accepted"
    );

    mac.send(step("pair_accept")).await;
    assert_eq!(laptop.next().await["type"], "pair_accept");
    mac.send(step("pair_reveal")).await;
    assert_eq!(
        mac.next().await["message"],
        "this pairing can't be revealed"
    );
    mac.send(step("pair_seal")).await;
    assert_eq!(mac.next().await["message"], "this pairing can't be sealed");

    // The codes differed: the Mac cancels, and the laptop hears.
    mac.send(json!({ "type": "pair_cancel", "pairing": pairing }))
        .await;
    assert_eq!(
        laptop.next().await,
        json!({ "type": "pair_closed", "pairing": pairing, "reason": "cancelled" })
    );
}

#[tokio::test]
async fn a_pairing_ends_after_five_minutes() {
    let server = start().await;
    let email = unique_email("expire");
    let mut mac = server.device(&email, "Mac").await.relay().await;
    let mut laptop = server.device(&email, "Laptop").await.relay().await;
    let pairing = requested(&mut laptop, &KeyPair::generate()).await;
    mac.next().await;

    sqlx::query("UPDATE pairings SET expires_at = expires_at - $1 WHERE id = $2")
        .bind(ilo_server::pairing::LIFETIME)
        .bind(&pairing)
        .execute(&server.db)
        .await
        .unwrap();
    mac.send(json!({ "type": "pair_accept", "pairing": pairing, "public_key": "k" }))
        .await;
    assert_eq!(mac.next().await["message"], "this pairing has expired");
    assert_eq!(
        laptop.next().await,
        json!({ "type": "pair_closed", "pairing": pairing, "reason": "expired" })
    );
}

#[tokio::test]
async fn an_account_makes_ten_requests_an_hour() {
    let server = start().await;
    let email = unique_email("limit");
    let mut laptop = server.device(&email, "Laptop").await.relay().await;
    let keys = KeyPair::generate();
    for _ in 0..ilo_server::pairing::REQUESTS_PER_HOUR {
        requested(&mut laptop, &keys).await;
    }
    laptop.send(pair_request(&keys)).await;
    assert_eq!(
        laptop.next().await["message"],
        "too many pairing requests; try again later"
    );
}
