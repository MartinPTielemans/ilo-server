mod common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::google::{from_google, google_tokens, to_google};
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
async fn a_send_api_that_fails_gets_the_page_an_smtp_failure_does() {
    use axum::http::StatusCode;
    let tried = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = tried.clone();
    let api = axum::Router::new().route(
        "/accounts/{account}/email/sending/send",
        axum::routing::post(move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { (StatusCode::INTERNAL_SERVER_ERROR, "{\"success\":false}") }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, api).await.unwrap() });
    let from = "ilo <sign-in@example.org>".parse().unwrap();
    let mailer = ilo_server::mail::Mailer::cloudflare(&api_url, "account", "token", from).unwrap();
    let server = start_with(mailer).await;
    let browser = browser();
    browser
        .get(server.authorize_url(&pkce(), "s"))
        .send()
        .await
        .unwrap();
    let page = browser
        .post(format!("{}/authorize/email", server.url))
        .form(&[("email", unique_email("api"))])
        .send()
        .await
        .unwrap();
    assert_eq!(tried.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        page.text()
            .await
            .unwrap()
            .contains("The server couldn&#39;t send mail.")
    );
}

#[tokio::test]
async fn an_address_whose_domain_takes_no_mail_gets_no_code_and_the_corrected_one_does() {
    let server = start().await;
    let browser = browser();
    browser
        .get(server.authorize_url(&pkce(), "s"))
        .send()
        .await
        .unwrap();
    let typed = format!("someone@{NO_MAIL}");
    let page = browser
        .post(format!("{}/authorize/email", server.url))
        .form(&[("email", &typed)])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("That address can&#39;t get mail."), "{page}");
    // The page keeps what was typed, to correct.
    assert!(page.contains(&typed), "{page}");
    assert!(server.mail.lock().unwrap().is_empty());

    let corrected = unique_email("corrected");
    let page = browser
        .post(format!("{}/authorize/email", server.url))
        .form(&[("email", &corrected)])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Check your email"), "{page}");
    let mail = server.mail.lock().unwrap();
    assert_eq!(mail.len(), 1);
    assert_eq!(mail[0].to, corrected);
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

/// A new sign-in from the client at `ip` asking for a code to `email`: the page it gets.
async fn ask_for_a_code(server: &Server, email: &str, ip: &str) -> String {
    let browser = browser();
    browser
        .get(server.authorize_url(&pkce(), "s"))
        .send()
        .await
        .unwrap();
    browser
        .post(format!("{}/authorize/email", server.url))
        .header("x-real-ip", ip)
        .form(&[("email", email)])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_client_gets_its_codes_an_hour_however_many_addresses_it_asks_for() {
    let server = start_alone(&[("CODES_PER_CLIENT_PER_HOUR", "2")]).await;
    let sent = || server.mail.lock().unwrap().len();
    for n in 1..=2 {
        let page = ask_for_a_code(&server, &unique_email("client"), "203.0.113.7").await;
        assert!(page.contains("Check your email"), "{page}");
        assert_eq!(sent(), n);
    }
    let page = ask_for_a_code(&server, &unique_email("client"), "203.0.113.7").await;
    assert!(page.contains("from your network"), "{page}");
    assert_eq!(
        sent(),
        2,
        "the client's third address in an hour mails nothing"
    );
    // The address it was refused for, which it didn't use up, gets one from elsewhere.
    let page = ask_for_a_code(&server, &unique_email("client"), "198.51.100.7").await;
    assert!(page.contains("Check your email"), "{page}");
    // A list names the client last, as a proxy appends the address it saw.
    let page = ask_for_a_code(&server, &unique_email("client"), "192.0.2.1, 203.0.113.7").await;
    assert!(page.contains("from your network"), "{page}");
}

#[tokio::test]
async fn an_ipv6_client_counts_by_its_network() {
    let server = start_alone(&[("CODES_PER_CLIENT_PER_HOUR", "1")]).await;
    let page = ask_for_a_code(&server, &unique_email("v6"), "2001:db8:1:2::1").await;
    assert!(page.contains("Check your email"), "{page}");
    let page = ask_for_a_code(&server, &unique_email("v6"), "2001:db8:1:2:ffff::9").await;
    assert!(page.contains("from your network"), "{page}");
    let page = ask_for_a_code(&server, &unique_email("v6"), "2001:db8:1:3::1").await;
    assert!(page.contains("Check your email"), "{page}");
}

#[tokio::test]
async fn the_server_mails_its_codes_a_day_and_a_refused_client_takes_none() {
    let server = start_alone(&[("CODES_PER_CLIENT_PER_HOUR", "1"), ("CODES_PER_DAY", "2")]).await;
    let sent = || server.mail.lock().unwrap().len();
    let page = ask_for_a_code(&server, &unique_email("day"), "203.0.113.1").await;
    assert!(page.contains("Check your email"), "{page}");
    // Refused for its client, so the day keeps the code.
    let page = ask_for_a_code(&server, &unique_email("day"), "203.0.113.1").await;
    assert!(page.contains("from your network"), "{page}");
    let page = ask_for_a_code(&server, &unique_email("day"), "203.0.113.2").await;
    assert!(page.contains("Check your email"), "{page}");
    let email = unique_email("day");
    let page = ask_for_a_code(&server, &email, "203.0.113.3").await;
    assert!(page.contains("all the codes it can for today"), "{page}");
    assert_eq!(sent(), 2);
    // The refusal gave back the address's and the client's codes.
    let left: Vec<(String, i64)> =
        sqlx::query_as("SELECT name, sent FROM code_limits WHERE name IN ($1, $2)")
            .bind(format!("address {email}"))
            .bind("client 203.0.113.3")
            .fetch_all(&server.db)
            .await
            .unwrap();
    assert!(left.iter().all(|(_, sent)| *sent == 0), "{left:?}");
}

#[tokio::test]
async fn sign_ins_asking_at_once_still_get_five_codes_an_hour() {
    let server = start().await;
    let email = unique_email("burst");
    let mut browsers = Vec::new();
    for _ in 0..20 {
        let browser = browser();
        browser
            .get(server.authorize_url(&pkce(), "s"))
            .send()
            .await
            .unwrap();
        browsers.push(browser);
    }
    let asks = browsers.iter().map(|browser| {
        browser
            .post(format!("{}/authorize/email", server.url))
            .form(&[("email", &email)])
            .send()
    });
    for response in futures_util::future::join_all(asks).await {
        assert_eq!(response.unwrap().status(), 200);
    }
    let sent = server.mail.lock().unwrap().len();
    assert!(sent <= 5, "{sent} codes were mailed to one address");
}

#[tokio::test]
async fn a_new_device_signing_in_is_mailed_to_the_account_but_the_first_isnt() {
    let server = start().await;
    let email = unique_email("notice");
    let notices = || {
        server
            .mail
            .lock()
            .unwrap()
            .iter()
            .filter(|mail| mail.to == email && mail.subject.contains("new device"))
            .cloned()
            .collect::<Vec<_>>()
    };
    server.device(&email, "Mac").await;
    server.device(&email, "Mallory\nlaptop").await;
    // The notice goes out beside the token answer, not before it.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while notices().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let notices = notices();
    assert_eq!(
        notices.len(),
        1,
        "only the second device is news: {notices:?}"
    );
    assert!(
        notices[0].body.contains("\"Mallory laptop\""),
        "the name, on one line: {}",
        notices[0].body
    );
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
async fn the_email_step_answers_alike_whether_or_not_an_address_has_a_passkey() {
    let server = start().await;
    let with = unique_email("has-passkey");
    server.add_passkey(&with).await;
    sqlx::query("UPDATE sign_in_codes SET sent_at = sent_at - 60")
        .execute(&server.db)
        .await
        .unwrap();
    let answer = |email: String| {
        let server = &server;
        async move {
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
            page.replace(&email, "ADDRESS")
        }
    };
    let without = answer(unique_email("no-account")).await;
    assert!(without.contains("Check your email"));
    assert_eq!(answer(with).await, without);
}

#[tokio::test]
async fn a_passkey_signs_in_without_an_address_or_its_credential_ids() {
    let server = start().await;
    let email = unique_email("discoverable");
    let mut passkey = server.add_passkey(&email).await;

    let browser = browser();
    let pkce = pkce();
    browser
        .get(server.authorize_url(&pkce, "state-1"))
        .send()
        .await
        .unwrap();
    let options: Value = browser
        .post(format!("{}/authorize/passkey/login", server.url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let named = options["publicKey"]["allowCredentials"]
        .as_array()
        .map_or(0, Vec::len);
    assert_eq!(named, 0, "the server names no credential: {options}");

    let finished: Value = browser
        .post(format!("{}/authorize/passkey/login/finish", server.url))
        .json(&passkey.get(&options, &server.url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(finished["redirect"], "/authorize/done");
    let page = browser
        .get(format!("{}/authorize/done", server.url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains(&email), "the account is the passkey's");
    let code = refresh_url(&page)
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned();
    let tokens = server.exchange(&code, &pkce.verifier, "Mac").await;
    assert_eq!(tokens.status(), 200);

    // A passkey for an account it doesn't belong to is refused.
    let other = unique_email("other");
    let mut stranger = server.add_passkey(&other).await;
    stranger.user = passkey.user.clone();
    let browser = common::browser();
    browser
        .get(server.authorize_url(&pkce, "s"))
        .send()
        .await
        .unwrap();
    let options: Value = browser
        .post(format!("{}/authorize/passkey/login", server.url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let refused = browser
        .post(format!("{}/authorize/passkey/login/finish", server.url))
        .json(&stranger.get(&options, &server.url))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 400);
}

#[tokio::test]
async fn a_new_passkey_is_asked_to_be_discoverable() {
    let server = start().await;
    let browser = browser();
    server
        .enter_code(&browser, &unique_email("resident"), &pkce())
        .await;
    let options: Value = browser
        .post(format!("{}/authorize/passkey/register", server.url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let selection = &options["publicKey"]["authenticatorSelection"];
    assert_eq!(selection["residentKey"], "required", "{options}");
    assert_eq!(selection["requireResidentKey"], true);
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
        let state = ilo_server::state(
            config(),
            ilo_server::mail::Mailer::Log,
            ilo_server::mail::Domains::except(&[]),
        )
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

async fn linked_account(server: &Server, person: &google::Person) -> Option<String> {
    sqlx::query_scalar(
        "SELECT account_id FROM identities WHERE provider = 'google' AND subject = $1",
    )
    .bind(&person.sub)
    .fetch_optional(&server.db)
    .await
    .unwrap()
}

async fn account_of(server: &Server, email: &str) -> Option<String> {
    ilo_server::accounts::find_by_email(&server.db, email)
        .await
        .unwrap()
}

/// Codes mailed to `email`, leaving out the new-device notices `/token` mails.
fn codes_to(server: &Server, email: &str) -> usize {
    let mail = server.mail.lock().unwrap();
    mail.iter()
        .filter(|mail| mail.to == email && mail.subject.ends_with("is your ilo sign-in code"))
        .count()
}

/// A Gmail address no other test uses: Google holds its mailbox.
fn gmail(name: &str) -> String {
    unique_email(name).replace("@example.org", "@gmail.com")
}

async fn subject(server: &Server, tokens: &Value) -> String {
    verified_claims(server, tokens["id_token"].as_str().unwrap()).await["sub"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn google_signs_up_a_new_address_and_signs_in_to_it_after() {
    let google = google::Google::start().await;
    let server = start_with_google(&google).await;
    let person = google::Person::new(&gmail("google-new"));

    let tokens = google_tokens(&server, &google, &person).await;
    let claims = verified_claims(&server, tokens["id_token"].as_str().unwrap()).await;
    assert_eq!(claims["email"], person.email);
    assert_eq!(claims["nonce"], "nonce-1");
    let account = claims["sub"].as_str().unwrap().to_owned();
    assert_eq!(
        linked_account(&server, &person).await,
        Some(account.clone())
    );
    assert_eq!(codes_to(&server, &person.email), 0, "no code is mailed");

    // The second time goes straight to the done page: the passkey was offered once.
    let browser = browser();
    let at_google = to_google(&server, &browser, &pkce()).await;
    let answer = from_google(&browser, google.sign_in(&at_google, &person)).await;
    server.done(&browser, answer).await;

    // Deleting the account removes the link with it.
    let deleted = reqwest::Client::new()
        .delete(format!("{}/api/account", server.url))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 204);
    assert_eq!(linked_account(&server, &person).await, None);
}

#[tokio::test]
async fn google_links_at_once_to_an_address_whose_mailbox_it_holds() {
    let google = google::Google::start().await;
    let server = start_with_google(&google).await;
    let gmail = google::Person::new(&gmail("gmail"));
    let mut workspace = google::Person::new(&unique_email("workspace"));
    workspace.hd = Some("example.org".into());
    for person in [gmail, workspace] {
        server.device(&person.email, "Mac").await;
        let account = account_of(&server, &person.email).await.unwrap();
        let mailed = codes_to(&server, &person.email);

        let tokens = google_tokens(&server, &google, &person).await;
        assert_eq!(subject(&server, &tokens).await, account, "{}", person.email);
        assert_eq!(linked_account(&server, &person).await, Some(account));
        assert_eq!(
            codes_to(&server, &person.email),
            mailed,
            "no code is mailed: {}",
            person.email
        );
    }
}

#[tokio::test]
async fn google_asks_for_the_mailed_code_before_linking_an_address_it_doesnt_hold() {
    let google = google::Google::start().await;
    let server = start_with_google(&google).await;
    let mut pages = Vec::new();
    for has_account in [true, false] {
        let mut person = google::Person::new(&unique_email("linking"));
        // A Workspace account, but on another domain than the address's.
        person.hd = Some("other.example.org".into());
        let account = if has_account {
            server.device(&person.email, "Mac").await;
            account_of(&server, &person.email).await
        } else {
            None
        };

        let browser = browser();
        let pkce = pkce();
        let at_google = to_google(&server, &browser, &pkce).await;
        let page = from_google(&browser, google.sign_in(&at_google, &person))
            .await
            .text()
            .await
            .unwrap();
        assert!(page.contains("To sign in with Google"), "{page}");
        pages.push(page.replace(&person.email, "ADDRESS"));
        assert_eq!(
            linked_account(&server, &person).await,
            None,
            "not before the code"
        );
        assert_eq!(account_of(&server, &person.email).await, account);

        let mut finished = browser
            .post(format!("{}/authorize/code", server.url))
            .form(&[("code", server.last_code(&person.email))])
            .send()
            .await
            .unwrap();
        if !has_account {
            assert!(finished.text().await.unwrap().contains("Add a passkey"));
            finished = browser
                .post(format!("{}/authorize/continue", server.url))
                .send()
                .await
                .unwrap();
        }
        let code = server.done(&browser, finished).await;
        let tokens: Value = server
            .exchange(&code, &pkce.verifier, "Mac")
            .await
            .json()
            .await
            .unwrap();
        let account = subject(&server, &tokens).await;
        assert_eq!(
            account_of(&server, &person.email).await.as_ref(),
            Some(&account)
        );
        assert_eq!(
            linked_account(&server, &person).await.as_ref(),
            Some(&account)
        );

        // From then on, Google signs in to it with no code.
        let mailed = codes_to(&server, &person.email);
        let tokens = google_tokens(&server, &google, &person).await;
        assert_eq!(subject(&server, &tokens).await, account);
        assert_eq!(codes_to(&server, &person.email), mailed);
    }
    assert_eq!(
        pages[0], pages[1],
        "the page doesn't say which addresses have accounts"
    );
}

#[tokio::test]
async fn a_code_for_another_address_links_no_waiting_google_account() {
    let google = google::Google::start().await;
    let server = start_with_google(&google).await;
    let person = google::Person::new(&unique_email("waiting"));
    server.device(&person.email, "Mac").await;

    let browser = browser();
    let at_google = to_google(&server, &browser, &pkce()).await;
    from_google(&browser, google.sign_in(&at_google, &person)).await;
    // The user goes back and signs in to another address of theirs with its code instead.
    let other = unique_email("other");
    browser
        .post(format!("{}/authorize/email", server.url))
        .form(&[("email", &other)])
        .send()
        .await
        .unwrap();
    let finished = browser
        .post(format!("{}/authorize/code", server.url))
        .form(&[("code", server.last_code(&other))])
        .send()
        .await
        .unwrap();
    assert!(finished.text().await.unwrap().contains("Add a passkey"));
    assert_eq!(linked_account(&server, &person).await, None);
}

#[tokio::test]
async fn a_google_account_whose_address_changed_still_finds_its_account() {
    let google = google::Google::start().await;
    let server = start_with_google(&google).await;
    let mut person = google::Person::new(&gmail("before"));
    let first = subject(&server, &google_tokens(&server, &google, &person).await).await;

    let before = person.email.clone();
    person.email = gmail("after");
    let browser = browser();
    let at_google = to_google(&server, &browser, &pkce()).await;
    let answer = from_google(&browser, google.sign_in(&at_google, &person)).await;
    assert_eq!(answer.status(), 303);
    let page = browser
        .get(format!("{}/authorize/done", server.url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains(&before), "the account's own address: {page}");
    assert_eq!(linked_account(&server, &person).await, Some(first));
    assert_eq!(
        account_of(&server, &person.email).await,
        None,
        "no second account"
    );
}

#[tokio::test]
async fn a_google_sign_in_that_fails_links_nothing() {
    let google = google::Google::start().await;
    let server = start_with_google(&google).await;
    let refused = async |person: &google::Person, back: &dyn Fn(&url::Url) -> url::Url| {
        let browser = browser();
        let at_google = to_google(&server, &browser, &pkce()).await;
        let page = from_google(&browser, back(&at_google)).await;
        assert_eq!(page.status(), 200);
        let page = page.text().await.unwrap();
        assert!(
            page.contains("Sign in to ilo"),
            "back to the first page: {page}"
        );
        assert_eq!(linked_account(&server, person).await, None);
        assert_eq!(account_of(&server, &person.email).await, None);
        page
    };

    let person = google::Person::new(&unique_email("forged"));
    let page = refused(&person, &|at_google| {
        let mut back = google.sign_in(at_google, &person);
        let pairs: Vec<(String, String)> = back.query_pairs().into_owned().collect();
        back.query_pairs_mut().clear();
        for (name, value) in pairs {
            let value = if name == "state" {
                "forged".into()
            } else {
                value
            };
            back.query_pairs_mut().append_pair(&name, &value);
        }
        back
    })
    .await;
    assert!(page.contains("didn&#39;t finish"), "{page}");

    let mut unverified = google::Person::new(&unique_email("unverified"));
    unverified.verified = false;
    let page = refused(&unverified, &|at_google| {
        google.sign_in(at_google, &unverified)
    })
    .await;
    assert!(page.contains("hasn&#39;t verified"), "{page}");

    let person = google::Person::new(&unique_email("refused"));
    let page = refused(&person, &|at_google| google.refuse(at_google)).await;
    assert!(page.contains("was cancelled"), "{page}");
}

#[tokio::test]
async fn google_answers_a_trip_once() {
    let google = google::Google::start().await;
    let server = start_with_google(&google).await;
    let person = google::Person::new(&unique_email("replay"));
    let browser = browser();
    let at_google = to_google(&server, &browser, &pkce()).await;
    let refusal = google.refuse(&at_google);
    let page = from_google(&browser, refusal).await.text().await.unwrap();
    assert!(page.contains("was cancelled"));
    // The trip's state is spent, so a code for it afterwards is refused.
    let page = from_google(&browser, google.sign_in(&at_google, &person))
        .await
        .text()
        .await
        .unwrap();
    assert!(page.contains("didn&#39;t finish"), "{page}");
    assert_eq!(linked_account(&server, &person).await, None);
}

#[tokio::test]
async fn a_server_says_whether_it_has_a_google_road() {
    async fn discovery(server: &Server) -> Value {
        reqwest::get(format!("{}/.well-known/openid-configuration", server.url))
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }
    let button = r#"href="/authorize/google/start""#;
    // A server that offers no Google road: no ilo_google, provider ignored, and no button.
    async fn no_road(server: &Server, button: &str, why: &str) {
        assert_eq!(discovery(server).await.get("ilo_google"), None, "{why}");
        let browser = browser();
        let page = browser
            .get(server.authorize_url(&pkce(), "s") + "&provider=google")
            .send()
            .await
            .unwrap();
        assert_eq!(page.status(), 200, "{why}: provider is ignored");
        let page = page.text().await.unwrap();
        assert!(
            page.contains("Sign in to ilo") && !page.contains("Google"),
            "{why}: {page}"
        );
        let page = browser
            .get(format!("{}/authorize/google/start", server.url))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(!page.contains(button), "{why}: {page}");
    }

    no_road(&start().await, button, "no Google client").await;
    let google = google::Google::start().await;
    let unoffered = start_with_vars(&google.client_vars()).await;
    no_road(&unoffered, button, "a Google client not offered yet").await;

    let server = start_with_google(&google).await;
    assert_eq!(discovery(&server).await["ilo_google"], true);
    let browser = common::browser();
    let page = browser
        .get(server.authorize_url(&pkce(), "s"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        page.contains(button) && page.contains("Continue with Google"),
        "{page}"
    );
    // The page's button goes on to Google with the same sign-in.
    let start = browser
        .get(format!("{}/authorize/google/start", server.url))
        .send()
        .await
        .unwrap();
    assert_eq!(start.status(), 303);
    let at_google = url::Url::parse(start.headers()["location"].to_str().unwrap()).unwrap();
    let person = google::Person::new(&gmail("button"));
    let answer = from_google(&browser, google.sign_in(&at_google, &person)).await;
    assert!(answer.text().await.unwrap().contains("Add a passkey"));
}

async fn listed_identities(server: &Server, token: &str) -> Value {
    let listed = reqwest::Client::new()
        .get(format!("{}/api/identities", server.url))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), 200);
    listed.json().await.unwrap()
}

async fn remove_google(server: &Server, token: &str) -> reqwest::StatusCode {
    reqwest::Client::new()
        .delete(format!("{}/api/identities/google", server.url))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn a_linked_google_sign_in_is_listed_and_removed_and_then_needs_the_mailed_code() {
    let google = google::Google::start().await;
    let server = start_with_google(&google).await;
    let person = google::Person::new(&gmail("removed"));
    let tokens = google_tokens(&server, &google, &person).await;
    let token = tokens["access_token"].as_str().unwrap();
    let account = subject(&server, &tokens).await;

    let listed = listed_identities(&server, token).await;
    let identities = listed["identities"].as_array().unwrap();
    assert_eq!(identities.len(), 1, "{listed}");
    assert_eq!(identities[0]["provider"], "google");
    assert_eq!(identities[0]["email"], person.email);
    assert!(identities[0]["linked_at"].as_i64().unwrap() > 0);
    assert!(
        !listed.to_string().contains(&person.sub),
        "Google's id isn't shown"
    );

    assert_eq!(remove_google(&server, token).await, 204);
    assert_eq!(
        listed_identities(&server, token).await["identities"],
        serde_json::json!([])
    );
    assert_eq!(linked_account(&server, &person).await, None);
    assert_eq!(
        remove_google(&server, token).await,
        404,
        "nothing left to remove"
    );

    // Google alone no longer signs in, even with the Gmail address Google holds.
    let browser = browser();
    let pkce = pkce();
    let at_google = to_google(&server, &browser, &pkce).await;
    let page = from_google(&browser, google.sign_in(&at_google, &person)).await;
    assert_eq!(page.status(), 200);
    assert!(
        page.text()
            .await
            .unwrap()
            .contains("To sign in with Google")
    );
    assert_eq!(linked_account(&server, &person).await, None);

    // The mailed code still signs in, from another tab.
    let device = server.device(&person.email, "Phone").await;
    let userinfo: Value = reqwest::Client::new()
        .get(format!("{}/userinfo", server.url))
        .bearer_auth(&device.access_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(userinfo["sub"], account.as_str());

    // And in the Google tab, entering the code links Google again: the user's own choice.
    sqlx::query("UPDATE sign_in_codes SET sent_at = sent_at - 60 WHERE email = $1")
        .bind(&person.email)
        .execute(&server.db)
        .await
        .unwrap();
    let page = browser
        .post(format!("{}/authorize/send-code", server.url))
        .send()
        .await
        .unwrap();
    assert!(page.text().await.unwrap().contains("We sent a new code."));
    let finished = browser
        .post(format!("{}/authorize/code", server.url))
        .form(&[("code", server.last_code(&person.email))])
        .send()
        .await
        .unwrap();
    server.done(&browser, finished).await;
    assert_eq!(linked_account(&server, &person).await, Some(account));
}
