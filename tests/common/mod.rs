//! A server on a free port with its own database, and a client that signs in
//! as ilo does: in a page, with the code from the mail.

#![allow(dead_code)]

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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (database_url, database) = match std::env::var("ILO_TEST_DATABASE_URL") {
        Ok(url) => (url, None),
        Err(_) => {
            let path = std::env::temp_dir().join(format!(
                "ilo-server-test-{}.db",
                ilo_server::db::random_id()
            ));
            (format!("sqlite:{}?mode=rwc", path.display()), Some(path))
        }
    };
    let config = Config::from_lookup(|name| match name {
        "DEV_MODE" => Some("1".into()),
        "PORT" => Some(port.to_string()),
        "PUBLIC_URL" => Some(format!("http://localhost:{port}")),
        "DATABASE_URL" => Some(database_url.clone()),
        _ => None,
    })
    .unwrap();
    let (mailer, mail) = Mailer::recording();
    let state = ilo_server::state(config, mailer).await.unwrap();
    tokio::spawn(async move {
        axum::serve(listener, ilo_server::router(state))
            .await
            .unwrap()
    });
    Server {
        url: format!("http://localhost:{port}"),
        mail,
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
            .find(|mail| mail.to == email)
            .expect("no code was mailed")
            .code
            .clone()
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

    /// Runs the sign-in pages to the redirect, and returns its authorization code.
    pub async fn authorization_code(&self, email: &str, pkce: &Pkce) -> String {
        let browser = browser();
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
        let page = browser
            .post(format!("{}/authorize/code", self.url))
            .form(&[("code", code)])
            .send()
            .await
            .unwrap();
        assert!(page.text().await.unwrap().contains("Add a passkey"));
        let redirect = browser
            .post(format!("{}/authorize/continue", self.url))
            .send()
            .await
            .unwrap();
        assert_eq!(redirect.status(), 303);
        let location = url::Url::parse(redirect.headers()["location"].to_str().unwrap()).unwrap();
        assert!(location.as_str().starts_with(REDIRECT));
        let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(query["state"], "state-1");
        assert_eq!(query["iss"], self.url);
        query["code"].clone()
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
    pub async fn command(
        &mut self,
        message: pb::ClientToServerMessage,
    ) -> pb::ClientToServerResponse {
        let response = reqwest::Client::new()
            .post(format!(
                "{}/command/?client=Chromium&client_id={}",
                self.server, self.cache_guid
            ))
            .bearer_auth(&self.access_token)
            .header("content-type", "application/octet-stream")
            .body(message.encode_to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let response = pb::ClientToServerResponse::decode(response.bytes().await.unwrap()).unwrap();
        if response.error_code() == pb::sync_enums::ErrorType::Success {
            self.birthday = response.store_birthday.clone();
        }
        response
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
