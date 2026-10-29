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
async fn a_signed_in_account_can_start_adding_a_passkey() {
    let server = start().await;
    let email = unique_email("passkey");
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
    let code = server.last_code(&email);
    browser
        .post(format!("{}/authorize/code", server.url))
        .form(&[("code", code)])
        .send()
        .await
        .unwrap();

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
}

#[tokio::test]
async fn health_answers_while_the_database_does() {
    let server = start().await;
    let response = reqwest::get(format!("{}/health", server.url))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}
