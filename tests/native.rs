//! The app's own sign-in road: the address and the code in the app's window, with no page.

mod common;

use common::*;
use serde_json::{Value, json};

async fn post(server: &Server, path: &str, body: Value) -> (u16, Value) {
    post_from(server, path, body, "127.0.0.1").await
}

async fn post_from(server: &Server, path: &str, body: Value, ip: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{}{path}", server.url))
        .header("x-real-ip", ip)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.headers()["cache-control"],
        "no-store",
        "{path} answers are never kept"
    );
    let status = response.status().as_u16();
    (status, response.json().await.unwrap())
}

async fn start_sign_in(server: &Server, email: &str, pkce: &Pkce) -> (u16, Value) {
    post(
        server,
        "/native/sign-in",
        json!({
            "client_id": "ilo",
            "code_challenge": pkce.challenge,
            "code_challenge_method": "S256",
            "email": email,
        }),
    )
    .await
}

async fn send_code(server: &Server, sign_in: &str, code: &str, verifier: &str) -> (u16, Value) {
    post(
        server,
        "/native/sign-in/code",
        json!({
            "sign_in": sign_in,
            "code": code,
            "code_verifier": verifier,
            "device_name": "Test Mac",
        }),
    )
    .await
}

fn wrong_code(right: &str) -> &'static str {
    if right == "000000" {
        "111111"
    } else {
        "000000"
    }
}

/// Lets `email` be mailed again at once, as 30 seconds later.
async fn wait_out_resend(server: &Server, email: &str) {
    sqlx::query("UPDATE sign_in_codes SET sent_at = sent_at - 60 WHERE email = $1")
        .bind(email)
        .execute(&server.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_address_and_the_mailed_code_give_the_tokens_token_gives() {
    let server = start().await;
    let email = unique_email("native");
    let pkce = pkce();
    let (status, started) = start_sign_in(&server, &email, &pkce).await;
    assert_eq!(status, 200);
    assert_eq!(started["resend_in"], 30);
    assert_eq!(started["expires_in"], 600);
    assert_eq!(started["can_resend"], true);
    let sign_in = started["sign_in"].as_str().unwrap();

    let code = server.last_code(&email);
    let (status, tokens) = send_code(&server, sign_in, &code, &pkce.verifier).await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["scope"], "openid email offline_access");
    let mut keys: Vec<_> = tokens.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "access_token",
            "expires_in",
            "id_token",
            "refresh_token",
            "scope",
            "token_type"
        ]
    );

    let devices: Value = reqwest::Client::new()
        .get(format!("{}/api/devices", server.url))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(devices["devices"][0]["name"], "Test Mac");

    // The refresh token is /token's own.
    let refreshed = reqwest::Client::new()
        .post(format!("{}/token", server.url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "ilo"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(refreshed.status(), 200);

    // The code and the sign-in are used up.
    let (status, again) = send_code(&server, sign_in, &code, &pkce.verifier).await;
    assert_eq!(status, 400);
    assert_eq!(again["error"], "sign_in_expired");
}

#[tokio::test]
async fn the_answer_is_the_same_whether_or_not_the_address_has_an_account() {
    let server = start().await;
    let known = unique_email("known");
    server.device(&known, "First Mac").await;
    wait_out_resend(&server, &known).await;
    let unknown = unique_email("unknown");
    let answer = |email: String| {
        let server = &server;
        async move {
            let (status, mut body) = start_sign_in(server, &email, &pkce()).await;
            body["sign_in"] = json!("ID");
            (status, body)
        }
    };
    assert_eq!(answer(known).await, answer(unknown).await);
}

#[tokio::test]
async fn a_wrong_code_is_refused_and_five_tries_spend_the_code() {
    let server = start().await;
    let email = unique_email("native-wrong");
    let pkce = pkce();
    let (_, started) = start_sign_in(&server, &email, &pkce).await;
    let sign_in = started["sign_in"].as_str().unwrap();
    let right = server.last_code(&email);
    for _ in 0..5 {
        let (status, refused) =
            send_code(&server, sign_in, wrong_code(&right), &pkce.verifier).await;
        assert_eq!(status, 400);
        assert_eq!(
            refused,
            json!({ "error": "wrong_code", "can_resend": true })
        );
    }
    let (status, refused) = send_code(&server, sign_in, &right, &pkce.verifier).await;
    assert_eq!(status, 400);
    assert_eq!(
        refused,
        json!({ "error": "too_many_tries", "can_resend": true })
    );
}

#[tokio::test]
async fn without_the_verifier_no_try_is_spent() {
    let server = start().await;
    let email = unique_email("native-verifier");
    let pkce = pkce();
    let (_, started) = start_sign_in(&server, &email, &pkce).await;
    let sign_in = started["sign_in"].as_str().unwrap();
    let right = server.last_code(&email);
    for _ in 0..10 {
        let (status, refused) = send_code(&server, sign_in, &right, &common::pkce().verifier).await;
        assert_eq!(status, 400);
        assert_eq!(refused["error"], "invalid_grant");
    }
    let (status, _) = send_code(&server, sign_in, &right, &pkce.verifier).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn an_expired_code_says_so() {
    let server = start().await;
    let email = unique_email("native-expired");
    let pkce = pkce();
    let (_, started) = start_sign_in(&server, &email, &pkce).await;
    let sign_in = started["sign_in"].as_str().unwrap();
    sqlx::query("UPDATE sign_in_codes SET expires_at = expires_at - 601 WHERE email = $1")
        .bind(&email)
        .execute(&server.db)
        .await
        .unwrap();
    let (status, refused) =
        send_code(&server, sign_in, &server.last_code(&email), &pkce.verifier).await;
    assert_eq!(status, 400);
    assert_eq!(refused, json!({ "error": "expired", "can_resend": true }));
}

#[tokio::test]
async fn the_right_code_sent_twice_at_once_signs_in_once() {
    let server = start().await;
    let email = unique_email("native-race");
    let pkce = pkce();
    let (_, started) = start_sign_in(&server, &email, &pkce).await;
    let sign_in = started["sign_in"].as_str().unwrap();
    let code = server.last_code(&email);
    let (a, b) = tokio::join!(
        send_code(&server, sign_in, &code, &pkce.verifier),
        send_code(&server, sign_in, &code, &pkce.verifier),
    );
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(statuses, [200, 400]);
}

#[tokio::test]
async fn a_sign_in_gets_one_new_code_after_the_wait() {
    let server = start().await;
    let email = unique_email("native-resend");
    let pkce = pkce();
    let (_, started) = start_sign_in(&server, &email, &pkce).await;
    let sign_in = started["sign_in"].as_str().unwrap();
    let first = server.last_code(&email);
    let resend = || {
        post(
            &server,
            "/native/sign-in/resend",
            json!({ "sign_in": sign_in }),
        )
    };

    // Within the wait, the code mailed stands and nothing is mailed.
    let (status, waiting) = resend().await;
    assert_eq!(status, 200);
    assert_eq!(waiting["can_resend"], true);
    assert_eq!(server.last_code(&email), first);

    wait_out_resend(&server, &email).await;
    let (status, sent) = resend().await;
    assert_eq!(status, 200);
    assert_eq!(sent["can_resend"], false);
    let second = server.last_code(&email);
    assert_ne!(second, first);

    wait_out_resend(&server, &email).await;
    let (status, refused) = resend().await;
    assert_eq!(status, 429);
    assert_eq!(refused["error"], "no_more_codes");

    let (status, _) = send_code(&server, sign_in, &second, &pkce.verifier).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn an_address_gets_five_codes_an_hour_on_this_road_too() {
    let server = start().await;
    let email = unique_email("native-limit");
    for _ in 0..5 {
        let (status, _) = start_sign_in(&server, &email, &pkce()).await;
        assert_eq!(status, 200);
        wait_out_resend(&server, &email).await;
    }
    let (status, refused) = start_sign_in(&server, &email, &pkce()).await;
    assert_eq!(status, 429);
    assert_eq!(refused["error"], "limit_address");
}

#[tokio::test]
async fn a_client_and_the_server_keep_their_limits_on_this_road_too() {
    let server = start_alone(&[("CODES_PER_CLIENT_PER_HOUR", "2"), ("CODES_PER_DAY", "3")]).await;
    let ask = |ip: &'static str| {
        let server = &server;
        async move {
            post_from(
                server,
                "/native/sign-in",
                json!({
                    "client_id": "ilo",
                    "code_challenge": pkce().challenge,
                    "code_challenge_method": "S256",
                    "email": unique_email("native-client"),
                }),
                ip,
            )
            .await
        }
    };
    assert_eq!(ask("192.0.2.1").await.0, 200);
    assert_eq!(ask("192.0.2.1").await.0, 200);
    assert_eq!(ask("192.0.2.1").await.1["error"], "limit_client");
    assert_eq!(ask("192.0.2.2").await.0, 200);
    assert_eq!(ask("192.0.2.3").await.1["error"], "limit_server");
}

#[tokio::test]
async fn an_address_that_is_wrong_or_takes_no_mail_gets_no_code() {
    let server = start().await;
    let (status, refused) = start_sign_in(&server, "not an address", &pkce()).await;
    assert_eq!(status, 400);
    assert_eq!(refused["error"], "invalid_email");
    let (status, refused) = start_sign_in(&server, &format!("someone@{NO_MAIL}"), &pkce()).await;
    assert_eq!(status, 400);
    assert_eq!(refused["error"], "undeliverable");
    assert!(server.mail.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_start_needs_ilo_and_an_s256_challenge() {
    let server = start().await;
    let email = unique_email("native-pkce");
    let ask = |client_id: &str, challenge: &str, method: &str| {
        post(
            &server,
            "/native/sign-in",
            json!({
                "client_id": client_id,
                "code_challenge": challenge,
                "code_challenge_method": method,
                "email": email,
            }),
        )
    };
    let challenge = pkce().challenge;
    assert_eq!(
        ask("other", &challenge, "S256").await.1["error"],
        "invalid_client"
    );
    assert_eq!(
        ask("ilo", &challenge, "plain").await.1["error"],
        "invalid_request"
    );
    assert_eq!(
        ask("ilo", "short", "S256").await.1["error"],
        "invalid_request"
    );
}

#[tokio::test]
async fn a_page_cant_post_to_it_as_a_form() {
    let server = start().await;
    let response = reqwest::Client::new()
        .post(format!("{}/native/sign-in", server.url))
        .form(&[("client_id", "ilo"), ("email", "someone@example.org")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 415);
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
}

#[tokio::test]
async fn discovery_says_the_app_can_sign_in_itself() {
    let server = start().await;
    let discovery: Value = reqwest::get(format!("{}/.well-known/openid-configuration", server.url))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(discovery["ilo_native_sign_in"], true);
}

#[tokio::test]
async fn the_passkey_road_draws_the_passkey_step_alone() {
    let server = start().await;
    let url = format!("{}&ilo_road=passkey", server.authorize_url(&pkce(), "s"));
    let page = browser()
        .get(url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains(r#"data-passkey="login""#));
    assert!(!page.contains(r#"name="email""#));
    assert!(!page.contains("Continue with Google"));

    // Without it, the first page is as it was.
    let page = browser()
        .get(server.authorize_url(&pkce(), "s"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains(r#"name="email""#));
    assert!(page.contains(r#"data-passkey="login""#));
}
