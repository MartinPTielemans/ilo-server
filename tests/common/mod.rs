//! A server on a free port with its own database, and a client that signs in
//! as ilo does: in a page, with the code from the mail.

#![allow(dead_code)]

pub mod passkey;

use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{SinkExt, StreamExt};
use ilo_server::config::Config;
use ilo_server::mail::{Mail, Mailer};
use ilo_server::pb;
use prost::Message as _;
use reqwest::redirect::Policy;
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

pub const REDIRECT: &str = "http://127.0.0.1:47123/callback";

pub struct Server {
    pub url: String,
    pub db: ilo_server::db::Db,
    pub mail: Arc<Mutex<Vec<Mail>>>,
    database: Option<std::path::PathBuf>,
}

impl Drop for Server {
    fn drop(&mut self) {
        // SQLite keeps working on an unlinked file until the test's runtime ends.
        if let Some(path) = &self.database {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
            }
        }
    }
}

/// Each test gets a fresh SQLite file, or shares the Postgres in
/// `ILO_TEST_DATABASE_URL` with addresses no other test uses.
pub async fn start() -> Server {
    let (mailer, mail) = Mailer::recording();
    let mut server = serve(mailer, &[], true).await;
    server.mail = mail;
    server
}

/// A server that sends its mail with `mailer`, which `Server::mail` doesn't see.
pub async fn start_with(mailer: Mailer) -> Server {
    serve(mailer, &[], true).await
}

/// A server on a fresh SQLite file, even when the tests share a Postgres, with
/// `vars` over the tests' settings: for limits that count every sign-in on the
/// server. Clients name their address in X-Real-IP.
pub async fn start_alone(vars: &[(&str, &str)]) -> Server {
    let (mailer, mail) = Mailer::recording();
    let mut server = serve(mailer, vars, false).await;
    server.mail = mail;
    server
}

async fn serve(mailer: Mailer, vars: &[(&str, &str)], shared: bool) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shared = std::env::var("ILO_TEST_DATABASE_URL")
        .ok()
        .filter(|_| shared);
    let (database_url, database) = match shared {
        Some(url) => (url, None),
        None => {
            let path = std::env::temp_dir().join(format!(
                "ilo-server-test-{}.db",
                ilo_server::db::random_id()
            ));
            (format!("sqlite:{}?mode=rwc", path.display()), Some(path))
        }
    };
    let set = |name: &str| vars.iter().find(|(key, _)| *key == name);
    let config = Config::from_lookup(|name| match name {
        _ if set(name).is_some() => set(name).map(|(_, value)| value.to_string()),
        // Tests sign in far more than a client does, and share the server's day on Postgres.
        "CODES_PER_CLIENT_PER_HOUR" | "CODES_PER_DAY" => Some("1000000".into()),
        "CLIENT_IP_HEADER" => Some("x-real-ip".into()),
        "DEV_MODE" => Some("1".into()),
        "PORT" => Some(port.to_string()),
        "PUBLIC_URL" => Some(format!("http://localhost:{port}")),
        "DATABASE_URL" => Some(database_url.clone()),
        _ => None,
    })
    .unwrap();
    let state = ilo_server::state(config, mailer).await.unwrap();
    let db = state.db.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            ilo_server::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    Server {
        url: format!("http://localhost:{port}"),
        db,
        mail: Arc::default(),
        database,
    }
}

pub fn unique_email(name: &str) -> String {
    format!(
        "{name}-{}@example.org",
        ilo_server::db::random_id()
            .to_lowercase()
            .replace(['-', '_'], "")
    )
}

pub fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap()
}

/// Where a page's `<meta http-equiv="refresh">` sends the tab.
pub fn refresh_url(html: &str) -> url::Url {
    let (_, rest) = html
        .split_once(r#"http-equiv="refresh" content="1; url="#)
        .expect("the page redirects");
    let (url, _) = rest.split_once('"').unwrap();
    url::Url::parse(&url.replace("&amp;", "&")).unwrap()
}

pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

pub fn pkce() -> Pkce {
    let verifier = URL_SAFE_NO_PAD.encode(ilo_server::db::random_bytes::<32>());
    let challenge = URL_SAFE_NO_PAD.encode(openssl::sha::sha256(verifier.as_bytes()));
    Pkce {
        verifier,
        challenge,
    }
}

impl Server {
    pub fn last_code(&self, email: &str) -> String {
        let mail = self.mail.lock().unwrap();
        mail.iter()
            .rev()
            .filter(|mail| mail.to == email)
            .find_map(|mail| mail.subject.strip_suffix(" is your ilo sign-in code"))
            .expect("no code was mailed")
            .to_owned()
    }

    pub fn authorize_url(&self, pkce: &Pkce, state: &str) -> String {
        let mut url = url::Url::parse(&format!("{}/authorize", self.url)).unwrap();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", "ilo")
            .append_pair("redirect_uri", REDIRECT)
            .append_pair("scope", "openid email offline_access")
            .append_pair("state", state)
            .append_pair("nonce", "nonce-1")
            .append_pair("code_challenge", &pkce.challenge)
            .append_pair("code_challenge_method", "S256");
        url.into()
    }

    /// Opens the sign-in pages in `browser`, enters `email`, and sends the
    /// mailed code: the answer is the passkey offer or the way to the done page.
    pub async fn enter_code(
        &self,
        browser: &reqwest::Client,
        email: &str,
        pkce: &Pkce,
    ) -> reqwest::Response {
        let page = browser
            .get(self.authorize_url(pkce, "state-1"))
            .send()
            .await
            .unwrap();
        assert_eq!(page.status(), 200);
        let page = browser
            .post(format!("{}/authorize/email", self.url))
            .form(&[("email", email)])
            .send()
            .await
            .unwrap();
        assert!(page.text().await.unwrap().contains("Check your email"));
        let code = self.last_code(email);
        browser
            .post(format!("{}/authorize/code", self.url))
            .form(&[("code", code)])
            .send()
            .await
            .unwrap()
    }

    /// Follows a finished sign-in to the done page, and returns the
    /// authorization code in the redirect it sends the tab on to.
    pub async fn done(&self, browser: &reqwest::Client, finished: reqwest::Response) -> String {
        assert_eq!(finished.status(), 303);
        assert_eq!(finished.headers()["location"], "/authorize/done");
        let page = browser
            .get(format!("{}/authorize/done", self.url))
            .send()
            .await
            .unwrap();
        assert_eq!(page.status(), 200);
        let location = refresh_url(&page.text().await.unwrap());
        assert!(location.as_str().starts_with(REDIRECT));
        let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(query["state"], "state-1");
        assert_eq!(query["iss"], self.url);
        query["code"].clone()
    }

    /// Runs the sign-in pages to the redirect, saying "Not now" to a passkey,
    /// and returns the authorization code.
    pub async fn authorization_code(&self, email: &str, pkce: &Pkce) -> String {
        let browser = browser();
        let mut answer = self.enter_code(&browser, email, pkce).await;
        if answer.status() == 200 {
            assert!(answer.text().await.unwrap().contains("Add a passkey"));
            answer = browser
                .post(format!("{}/authorize/continue", self.url))
                .send()
                .await
                .unwrap();
        }
        self.done(&browser, answer).await
    }

    /// Signs `email` in for the first time and takes the passkey offer.
    pub async fn add_passkey(&self, email: &str) -> passkey::SoftPasskey {
        let browser = browser();
        let offer = self.enter_code(&browser, email, &pkce()).await;
        assert!(offer.text().await.unwrap().contains("Add a passkey"));
        let options: Value = browser
            .post(format!("{}/authorize/passkey/register", self.url))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let (passkey, credential) = passkey::SoftPasskey::create(&options, &self.url);
        let added = browser
            .post(format!("{}/authorize/passkey/register/finish", self.url))
            .json(&credential)
            .send()
            .await
            .unwrap();
        assert_eq!(added.status(), 200, "{}", added.text().await.unwrap());
        passkey
    }

    pub async fn exchange(
        &self,
        code: &str,
        verifier: &str,
        device_name: &str,
    ) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/token", self.url))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", REDIRECT),
                ("client_id", "ilo"),
                ("code_verifier", verifier),
                ("device_name", device_name),
            ])
            .send()
            .await
            .unwrap()
    }

    /// A signed-in device: what ilo holds after the sign-in tab closes.
    pub async fn device(&self, email: &str, name: &str) -> Client {
        let pkce = pkce();
        let code = self.authorization_code(email, &pkce).await;
        let tokens: Value = self
            .exchange(&code, &pkce.verifier, name)
            .await
            .json()
            .await
            .unwrap();
        Client {
            server: self.url.clone(),
            access_token: tokens["access_token"].as_str().unwrap().to_owned(),
            refresh_token: tokens["refresh_token"].as_str().unwrap().to_owned(),
            cache_guid: ilo_server::db::random_id(),
            birthday: None,
        }
    }
}

pub struct Client {
    pub server: String,
    pub access_token: String,
    pub refresh_token: String,
    pub cache_guid: String,
    pub birthday: Option<String>,
}

pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

pub fn gunzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_end(&mut decoded)
        .unwrap();
    decoded
}

pub const PREFERENCES: i32 = 37702;
pub const BOOKMARKS: i32 = 32904;
pub const NIGORI: i32 = 47745;

/// Specifics as a client with a custom passphrase sends them: `encrypted`
/// (field 1) with ciphertext, and the data type's field, empty.
pub fn encrypted_specifics(data_type: i32, ciphertext: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    prost::encoding::bytes::encode(1, &ciphertext.to_vec(), &mut bytes);
    bytes.extend(ilo_server::sync::empty_specifics(data_type));
    bytes
}

pub fn marker(data_type: i32, token: Option<Vec<u8>>) -> pb::DataTypeProgressMarker {
    pb::DataTypeProgressMarker {
        data_type_id: Some(data_type),
        token,
        ..Default::default()
    }
}

impl Client {
    /// Sends a message as Chromium's engine does: gzipped, offering gzip back.
    pub async fn command(
        &mut self,
        message: pb::ClientToServerMessage,
    ) -> pb::ClientToServerResponse {
        let response = self
            .post_command(gzip(&message.encode_to_vec()), true)
            .await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-encoding"], "gzip");
        let body = gunzip(&response.bytes().await.unwrap());
        let response = pb::ClientToServerResponse::decode(body.as_slice()).unwrap();
        if response.error_code() == pb::sync_enums::ErrorType::Success {
            self.birthday = response.store_birthday.clone();
        }
        response
    }

    pub async fn post_command(&self, body: Vec<u8>, gzipped: bool) -> reqwest::Response {
        let mut request = reqwest::Client::new()
            .post(format!(
                "{}/command/?client=Chromium&client_id={}",
                self.server, self.cache_guid
            ))
            .bearer_auth(&self.access_token)
            .header("content-type", "application/octet-stream");
        if gzipped {
            request = request
                .header("content-encoding", "gzip")
                .header("accept-encoding", "gzip, deflate, br, zstd");
        }
        request.body(body).send().await.unwrap()
    }

    fn message(
        &self,
        contents: pb::client_to_server_message::Contents,
    ) -> pb::ClientToServerMessage {
        let mut message = pb::ClientToServerMessage {
            share: String::new(),
            store_birthday: self.birthday.clone(),
            ..Default::default()
        };
        message.set_message_contents(contents);
        message
    }

    pub async fn get_updates(
        &mut self,
        markers: Vec<pb::DataTypeProgressMarker>,
    ) -> pb::ClientToServerResponse {
        let mut message = self.message(pb::client_to_server_message::Contents::GetUpdates);
        message.get_updates = Some(pb::GetUpdatesMessage {
            from_progress_marker: markers,
            need_encryption_key: Some(true),
            ..Default::default()
        });
        self.command(message).await
    }

    pub async fn commit(&mut self, entries: Vec<pb::SyncEntity>) -> pb::ClientToServerResponse {
        let mut message = self.message(pb::client_to_server_message::Contents::Commit);
        message.commit = Some(pb::CommitMessage {
            entries,
            cache_guid: Some(self.cache_guid.clone()),
            ..Default::default()
        });
        self.command(message).await
    }

    pub async fn clear_server_data(&mut self) -> pb::ClientToServerResponse {
        let message = self.message(pb::client_to_server_message::Contents::ClearServerData);
        self.command(message).await
    }

    pub async fn relay(&self) -> Relay {
        let url = self.server.replace("http://", "ws://") + "/relay";
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {}", self.access_token).parse().unwrap(),
        );
        let (socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        let mut relay = Relay {
            socket,
            device: String::new(),
        };
        let hello = relay.next().await;
        assert_eq!(hello["type"], "hello");
        relay.device = hello["device"].as_str().unwrap().to_owned();
        relay
    }
}

pub struct Relay {
    pub socket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    pub device: String,
}

impl Relay {
    /// The next JSON frame, waiting at most five seconds.
    pub async fn next(&mut self) -> Value {
        match self.frame().await {
            Message::Text(text) => serde_json::from_str(&text).unwrap(),
            other => panic!("expected a text frame, got {other:?}"),
        }
    }

    pub async fn frame(&mut self) -> Message {
        loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(5), self.socket.next())
                .await
                .expect("the relay sent nothing")
                .expect("the relay closed")
                .expect("the relay failed");
            if !matches!(frame, Message::Ping(_) | Message::Pong(_)) {
                return frame;
            }
        }
    }

    pub async fn send(&mut self, frame: Value) {
        self.socket
            .send(Message::Text(frame.to_string().into()))
            .await
            .unwrap();
    }
}

pub fn close_code(frame: &Message) -> Option<u16> {
    match frame {
        Message::Close(Some(close)) => Some(close.code.into()),
        _ => None,
    }
}
