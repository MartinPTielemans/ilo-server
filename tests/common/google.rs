//! A stand-in Google on loopback: its token endpoint, and the user signing in on its page. The
//! server reaches it through `GOOGLE_TEST_URL`, which only DEV_MODE honours.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use url::Url;

pub const CLIENT_ID: &str = "ilo-test.apps.googleusercontent.com";
pub const CLIENT_SECRET: &str = "stand-in-client-secret";

/// A Google account.
pub struct Person {
    pub sub: String,
    pub email: String,
    pub verified: bool,
    /// Its Google Workspace domain.
    pub hd: Option<String>,
}

impl Person {
    pub fn new(email: &str) -> Self {
        Self {
            sub: format!(
                "1{}",
                u64::from_le_bytes(ilo_server::db::random_bytes::<8>())
            ),
            email: email.to_owned(),
            verified: true,
            hd: None,
        }
    }
}

struct Issued {
    claims: Value,
    challenge: String,
    redirect_uri: String,
}

#[derive(Clone, Default)]
struct Codes(Arc<Mutex<HashMap<String, Issued>>>);

pub struct Google {
    pub url: String,
    codes: Codes,
}

impl Google {
    pub async fn start() -> Self {
        let codes = Codes::default();
        let app = axum::Router::new()
            .route("/token", axum::routing::post(token))
            .with_state(codes.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, codes }
    }

    /// The settings that make a server Google's client, at this stand-in.
    pub fn vars(&self) -> [(&str, &str); 3] {
        [
            ("GOOGLE_CLIENT_ID", CLIENT_ID),
            ("GOOGLE_CLIENT_SECRET", CLIENT_SECRET),
            ("GOOGLE_TEST_URL", &self.url),
        ]
    }

    /// Checks the request the server sent the tab to Google with, as Google's page reads it.
    fn read(&self, authorization: &Url) -> HashMap<String, String> {
        assert_eq!(
            authorization.as_str().split('?').next().unwrap(),
            format!("{}/auth", self.url)
        );
        let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], CLIENT_ID);
        assert_eq!(query["scope"], "openid email", "nothing past the address");
        assert_eq!(query["prompt"], "select_account");
        assert_eq!(query["code_challenge_method"], "S256");
        assert!(
            !query.contains_key("access_type"),
            "no refresh token is asked for"
        );
        query
    }

    /// `person` signs in on Google's page: where Google sends the tab back to.
    pub fn sign_in(&self, authorization: &Url, person: &Person) -> Url {
        let query = self.read(authorization);
        let mut claims = json!({
            "iss": self.url,
            "aud": CLIENT_ID,
            "azp": CLIENT_ID,
            "iat": ilo_server::db::now(),
            "exp": ilo_server::db::now() + 3600,
            "nonce": query["nonce"],
            "sub": person.sub,
            "email": person.email,
            "email_verified": person.verified,
            "name": "Someone",
            "picture": "https://example.org/picture.png",
        });
        if let Some(hd) = &person.hd {
            claims["hd"] = json!(hd);
        }
        let code = format!("4/{}", ilo_server::db::random_id());
        self.codes.0.lock().unwrap().insert(
            code.clone(),
            Issued {
                claims,
                challenge: query["code_challenge"].clone(),
                redirect_uri: query["redirect_uri"].clone(),
            },
        );
        back(&query, &[("code", &code), ("state", &query["state"])])
    }

    /// The user refuses on Google's page.
    pub fn refuse(&self, authorization: &Url) -> Url {
        let query = self.read(authorization);
        back(
            &query,
            &[("error", "access_denied"), ("state", &query["state"])],
        )
    }
}

fn back(query: &HashMap<String, String>, params: &[(&str, &str)]) -> Url {
    let mut url = Url::parse(&query["redirect_uri"]).unwrap();
    url.query_pairs_mut().extend_pairs(params);
    url
}

/// Google's token endpoint: the code once, for the client with its secret and the PKCE
/// verifier the authorization request committed to.
async fn token(State(codes): State<Codes>, Form(form): Form<HashMap<String, String>>) -> Response {
    let refused = || {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response()
    };
    let field = |name: &str| form.get(name).map_or("", String::as_str);
    let Some(issued) = codes.0.lock().unwrap().remove(field("code")) else {
        return refused();
    };
    let challenge = URL_SAFE_NO_PAD.encode(openssl::sha::sha256(field("code_verifier").as_bytes()));
    if field("grant_type") != "authorization_code"
        || field("client_id") != CLIENT_ID
        || field("client_secret") != CLIENT_SECRET
        || field("redirect_uri") != issued.redirect_uri
        || challenge != issued.challenge
    {
        return refused();
    }
    let part = |value: &Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let id_token = format!(
        "{}.{}.{}",
        part(&json!({"alg": "RS256", "kid": "stand-in"})),
        part(&issued.claims),
        URL_SAFE_NO_PAD.encode("not checked: the token comes straight from Google over TLS")
    );
    Json(json!({
        "access_token": "ya29.stand-in-access-token",
        "expires_in": 3599,
        "scope": "openid https://www.googleapis.com/auth/userinfo.email",
        "token_type": "Bearer",
        "id_token": id_token,
    }))
    .into_response()
}
