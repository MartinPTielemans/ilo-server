mod common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use serde_json::Value;

#[tokio::test]
async fn signing_in_with_a_mailed_code_gives_a_device_its_tokens() {
    let server = start().await;
    let email = unique_email("code");
    let pkce = pkce();
    let code = server.authorization_code(&email, &pkce).await;

    let response = server.exchange(&code, &pkce.verifier, "Test Mac").await;
    assert_eq!(response.status(), 200);
    let tokens: Value = response.json().await.unwrap();
    assert_eq!(tokens["token_type"], "Bearer");

    let claims = verified_claims(&server, tokens["id_token"].as_str().unwrap()).await;
    assert_eq!(claims["iss"], server.url);
    assert_eq!(claims["aud"], "ilo");
    assert_eq!(claims["email"], email);
    assert_eq!(claims["nonce"], "nonce-1");

    let userinfo: Value = reqwest::Client::new()
        .get(format!("{}/userinfo", server.url))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(userinfo["sub"], claims["sub"]);
    assert_eq!(userinfo["email"], email);

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
    assert_eq!(devices["devices"][0]["current"], true);

    // A code works once.
    let again = server.exchange(&code, &pkce.verifier, "Test Mac").await;
    assert_eq!(again.status(), 400);
}

/// Checks the ID token's ES256 signature against the server's published key.
async fn verified_claims(server: &Server, id_token: &str) -> Value {
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;

    let discovery: Value = reqwest::get(format!("{}/.well-known/openid-configuration", server.url))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let jwks: Value = reqwest::get(discovery["jwks_uri"].as_str().unwrap())
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = &jwks["keys"][0];
    let coordinate = |name: &str| {
        BigNum::from_slice(&URL_SAFE_NO_PAD.decode(key[name].as_str().unwrap()).unwrap()).unwrap()
    };
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let public =
        EcKey::from_public_key_affine_coordinates(&group, &coordinate("x"), &coordinate("y"))
            .unwrap();

    let (input, signature) = id_token.rsplit_once('.').unwrap();
    let signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
    let signature = EcdsaSig::from_private_components(
        BigNum::from_slice(&signature[..32]).unwrap(),
        BigNum::from_slice(&signature[32..]).unwrap(),
    )
    .unwrap();
    assert!(
        signature
            .verify(&openssl::sha::sha256(input.as_bytes()), &public)
            .unwrap()
    );
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(input.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["kid"], key["kid"]);
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(input.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn a_wrong_code_is_refused_and_counts_against_the_limit() {
    let server = start().await;
    let email = unique_email("wrong");
    let browser = browser();
    browser
        .get(server.authorize_url(&pkce(), "s"))
        .send()
        .await
        .unwrap();
    browser
        .post(format!("{}/authorize/email", server.url))
        .form(&[("email", &email)])
        .send()
        .await
        .unwrap();
    let right = server.last_code(&email);
    let wrong = if right == "000000" {
        "111111"
    } else {
        "000000"
    };
    for _ in 0..5 {
        let page = browser
            .post(format!("{}/authorize/code", server.url))
            .form(&[("code", wrong)])
            .send()
            .await
            .unwrap();
        assert!(page.text().await.unwrap().contains("isn&#39;t right"));
    }
    let page = browser
        .post(format!("{}/authorize/code", server.url))
        .form(&[("code", &right)])
        .send()
        .await
        .unwrap();
    assert!(page.text().await.unwrap().contains("Too many tries"));
}

#[tokio::test]
async fn tries_sent_at_once_count_against_the_limit_too() {
    let server = start().await;
    let email = unique_email("race");
    let browser = browser();
    browser
        .get(server.authorize_url(&pkce(), "s"))
        .send()
        .await
        .unwrap();
    browser
        .post(format!("{}/authorize/email", server.url))
        .form(&[("email", &email)])
        .send()
        .await
        .unwrap();
    let right = server.last_code(&email);
    // Thirty different wrong codes at once, as a script guessing would send them.
    let tries = (0..30).map(|n| {
        let code = format!("{:06}", (right.parse::<u32>().unwrap() + 1 + n) % 1_000_000);
        let request = browser
            .post(format!("{}/authorize/code", server.url))
            .form(&[("code", code)])
            .send();
        async move { request.await.unwrap().text().await.unwrap() }
    });
    let pages = futures_util::future::join_all(tries).await;
    let checked = pages
        .iter()
        .filter(|page| page.contains("isn&#39;t right"))
        .count();
    assert!(
        checked <= 5,
        "{checked} codes were checked, past the limit of 5"
    );
    let page = browser
        .post(format!("{}/authorize/code", server.url))
        .form(&[("code", &right)])
        .send()
        .await
        .unwrap();
    assert!(page.text().await.unwrap().contains("Too many tries"));
}

#[tokio::test]
async fn an_address_gets_five_codes_an_hour_however_many_sign_ins_ask() {
    let server = start().await;
    let email = unique_email("capped");
    let sent = || server.mail.lock().unwrap().len();
    for n in 1..=6 {
        let browser = browser();
        browser
            .get(server.authorize_url(&pkce(), "s"))
            .send()
            .await
            .unwrap();
        let page = browser
            .post(format!("{}/authorize/email", server.url))
            .form(&[("email", &email)])
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        if n <= 5 {
            assert_eq!(sent(), n, "sign-in {n} mails a code");
            assert!(page.contains("Check your email"));
        } else {
            assert_eq!(sent(), 5, "the sixth in an hour mails nothing");
            assert!(page.contains("too many codes"), "{page}");
        }
        // Past the wait between two codes to one address.
        sqlx::query("UPDATE sign_in_codes SET sent_at = sent_at - 60 WHERE email = $1")
            .bind(&email)
            .execute(&server.db)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn the_code_flow_needs_pkce_and_a_known_redirect() {
    let server = start().await;
    let unknown = server
        .authorize_url(&pkce(), "s")
        .replace("127.0.0.1%3A47123", "evil.example");
    let page = browser().get(unknown).send().await.unwrap();
    assert_eq!(page.status(), 400);

    let pkce = pkce();
    let code = server
        .authorization_code(&unique_email("pkce"), &pkce)
        .await;
    let response = server.exchange(&code, "not-the-verifier", "Test").await;
    assert_eq!(response.status(), 400);
    let error: Value = response.json().await.unwrap();
    assert_eq!(error["error"], "invalid_grant");
}

#[tokio::test]
async fn a_pages_steps_need_the_cookie_of_the_browser_that_started_it() {
    let server = start().await;
    let started = browser();
    started
        .get(server.authorize_url(&pkce(), "s"))
        .send()
        .await
        .unwrap();
    let other = browser();
    let page = other
        .post(format!("{}/authorize/email", server.url))
        .form(&[("email", unique_email("cookie"))])
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 400);
    assert!(page.text().await.unwrap().contains("expired"));
}

#[tokio::test]
async fn refreshing_rotates_the_refresh_token_and_revoking_signs_the_device_out() {
    let server = start().await;
    let device = server.device(&unique_email("refresh"), "Test").await;
    let refresh = |token: String| {
        let url = format!("{}/token", server.url);
        async move {
            reqwest::Client::new()
                .post(url)
                .form(&[("grant_type", "refresh_token"), ("refresh_token", &token)])
                .send()
                .await
                .unwrap()
        }
    };
    let renewed: Value = refresh(device.refresh_token.clone())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        refresh(device.refresh_token.clone()).await.status(),
        400,
        "an old refresh token stops working"
    );
    let access = renewed["access_token"].as_str().unwrap().to_owned();
    let userinfo = |token: String| {
        let url = format!("{}/userinfo", server.url);
        async move {
            reqwest::Client::new()
                .get(url)
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(userinfo(access.clone()).await, 200);

    let revoked = reqwest::Client::new()
        .post(format!("{}/revoke", server.url))
        .form(&[("token", renewed["refresh_token"].as_str().unwrap())])
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 200);
    assert_eq!(
        userinfo(access).await,
        401,
        "revoking the refresh token removes the device"
    );
}

#[tokio::test]
async fn a_refresh_token_renews_once_even_when_two_refreshes_race() {
    let server = start().await;
    let device = server.device(&unique_email("race-refresh"), "Test").await;
    let refreshes = (0..10).map(|_| {
        reqwest::Client::new()
            .post(format!("{}/token", server.url))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", device.refresh_token.as_str()),
            ])
            .send()
    });
    let answers = futures_util::future::join_all(refreshes).await;
    let renewed = answers
        .iter()
        .filter(|answer| answer.as_ref().unwrap().status() == 200)
        .count();
    assert_eq!(renewed, 1, "a copied refresh token can't fork the device");
}

#[tokio::test]
async fn a_passkey_is_offered_once_after_the_first_sign_in() {
    let server = start().await;
    let email = unique_email("passkey");
    let browser = browser();
    let offer = server.enter_code(&browser, &email, &pkce()).await;
    assert_eq!(offer.status(), 200);
    assert!(offer.text().await.unwrap().contains("Not now"));

    // The ceremony's options, which the page hands to navigator.credentials.create.
    let options: Value = browser
        .post(format!("{}/authorize/passkey/register", server.url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(options["publicKey"]["rp"]["id"], "localhost");
    assert_eq!(options["publicKey"]["user"]["name"], email);

    let again = common::browser();
    let finished = server.enter_code(&again, &email, &pkce()).await;
    assert_eq!(
        finished.status(),
        303,
        "the second sign-in goes straight on"
    );
    server.done(&again, finished).await;
}

#[tokio::test]
async fn the_code_page_says_when_it_expires_and_sends_one_new_code() {
    let server = start().await;
    let email = unique_email("resend");
    let browser = browser();
    browser
        .get(server.authorize_url(&pkce(), "state-1"))
        .send()
        .await
        .unwrap();
    let page = browser
        .post(format!("{}/authorize/email", server.url))
        .form(&[("email", &email)])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("It expires in 10 minutes."));
    assert!(page.contains("Send a new code"));
    let first = server.last_code(&email);
    let send_again = || async {
        browser
            .post(format!("{}/authorize/send-code", server.url))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    };
    let sent = || server.mail.lock().unwrap().len();

    let page = send_again().await;
    assert!(
        page.contains("a moment ago"),
        "pressing at once mails nothing"
    );
    assert_eq!(sent(), 1);

    let a_minute_ago = || async {
        sqlx::query("UPDATE sign_in_codes SET sent_at = sent_at - 60 WHERE email = $1")
            .bind(&email)
            .execute(&server.db)
            .await
            .unwrap();
    };
    a_minute_ago().await;
    let page = send_again().await;
    assert_eq!(sent(), 2);
    assert!(page.contains("We sent a new code."));
    assert!(!page.contains("Send a new code"), "one new code, no more");

    a_minute_ago().await;
    let page = send_again().await;
    assert_eq!(sent(), 2);
    assert!(page.contains("can&#39;t send another code"));

    let code = |code: String| {
        browser
            .post(format!("{}/authorize/code", server.url))
            .form(&[("code", code)])
            .send()
    };
    let new = server.last_code(&email);
    if new != first {
        let refused = code(first).await.unwrap();
        assert_eq!(refused.status(), 400, "the new code replaces the first");
    }
    let offer = code(new).await.unwrap();
    assert!(offer.text().await.unwrap().contains("Add a passkey"));
}

#[tokio::test]
async fn the_done_page_hands_the_code_back_once() {
    let server = start().await;
    let email = unique_email("done");
    let browser = browser();
    server.enter_code(&browser, &email, &pkce()).await;
    let finished = browser
        .post(format!("{}/authorize/continue", server.url))
        .send()
        .await
        .unwrap();

    // Going back to a step of a finished sign-in leads to its done page.
    let back = browser
        .post(format!("{}/authorize/code", server.url))
        .form(&[("code", "000000")])
        .send()
        .await
        .unwrap();
    assert_eq!(back.headers()["location"], "/authorize/done");

    server.done(&browser, finished).await;
    let again = browser
        .get(format!("{}/authorize/done", server.url))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 400);
    assert!(again.text().await.unwrap().contains("Can't sign in"));
}

#[tokio::test]
async fn the_pages_run_nothing_inline_and_send_no_referrer() {
    let server = start().await;
    let page = browser()
        .get(server.authorize_url(&pkce(), "s"))
        .send()
        .await
        .unwrap();
    let policy = page.headers()["content-security-policy"].to_str().unwrap();
    for directive in [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ] {
        assert!(policy.contains(directive), "{directive} in {policy}");
    }
    assert!(!policy.contains("unsafe"));
    assert_eq!(page.headers()["referrer-policy"], "no-referrer");
    let html = page.text().await.unwrap();
    assert_eq!(html.matches("<script").count(), 1);
    assert!(html.contains(r#"<script src="/sign-in.js" defer></script>"#));
    assert!(!html.contains("<style") && !html.contains(" style="));

    for (path, kind) in [
        ("/sign-in.css", "text/css"),
        ("/sign-in.js", "text/javascript"),
    ] {
        let asset = reqwest::get(format!("{}{path}", server.url)).await.unwrap();
        assert_eq!(asset.status(), 200);
        let content_type = asset.headers()["content-type"].to_str().unwrap();
        assert!(content_type.starts_with(kind), "{path} is {content_type}");
    }
}

#[tokio::test]
async fn a_mailed_code_signs_a_device_in_to_sync() {
    let server = start().await;
    let mut device = server.device(&unique_email("sync"), "Test").await;
    let response = device.get_updates(vec![marker(NIGORI, None)]).await;
    assert_eq!(
        response.error_code(),
        ilo_server::pb::sync_enums::ErrorType::Success
    );
    let updates = response.get_updates.unwrap();
    assert!(
        updates
            .entries
            .iter()
            .any(|entity| entity.server_defined_unique_tag() == "google_chrome_nigori")
    );
    assert!(!updates.encryption_keys.is_empty());
}

#[tokio::test]
async fn health_answers_while_the_database_does() {
    let server = start().await;
    let response = reqwest::get(format!("{}/health", server.url))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn a_restarted_server_keeps_its_signing_key() {
    let path = std::env::temp_dir().join(format!(
        "ilo-server-restart-{}.db",
        ilo_server::db::random_id()
    ));
    let url = format!("sqlite:{}?mode=rwc", path.display());
    let config = || {
        ilo_server::config::Config::from_lookup(|name| match name {
            "DEV_MODE" => Some("1".into()),
            "DATABASE_URL" => Some(url.clone()),
            _ => None,
        })
        .unwrap()
    };
    let mut keys = Vec::new();
    for _ in 0..2 {
        let state = ilo_server::state(config(), ilo_server::mail::Mailer::Log)
            .await
            .unwrap();
        let rows: Vec<String> = sqlx::query_scalar("SELECT id FROM signing_keys")
            .fetch_all(&state.db)
            .await
            .unwrap();
        keys.push(rows);
        state.db.close().await;
    }
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    assert_eq!(keys[0].len(), 1);
    assert_eq!(keys[0], keys[1]);
}
