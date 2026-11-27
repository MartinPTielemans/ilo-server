//! Signing in with Google, with the server as Google's client the way ilo is the server's: the
//! code flow with PKCE, from the sign-in window. Google's answer is read once, in the request
//! that gets it, for its `sub` and address. No Google token is kept or logged, and no refresh
//! token is asked for.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::config::{Config, Google};
use crate::db;

/// `/authorize`'s `provider` for this road, and the provider `identities` names.
pub const PROVIDER: &str = "google";

/// What one trip to Google is checked against when it comes back.
pub struct Leg {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
}

impl Leg {
    pub fn fresh() -> Self {
        Self {
            state: db::random_id(),
            nonce: db::random_id(),
            verifier: URL_SAFE_NO_PAD.encode(db::random_bytes::<32>()),
        }
    }
}

/// Where Google sends the tab back to, which Google's client lists.
pub fn redirect_uri(config: &Config) -> String {
    config.url("/authorize/google")
}

pub fn authorization_url(config: &Config, google: &Google, leg: &Leg) -> anyhow::Result<String> {
    let challenge = URL_SAFE_NO_PAD.encode(openssl::sha::sha256(leg.verifier.as_bytes()));
    let mut url = Url::parse(&google.authorization_endpoint)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &google.client_id)
        .append_pair("redirect_uri", &redirect_uri(config))
        .append_pair("scope", "openid email")
        .append_pair("state", &leg.state)
        .append_pair("nonce", &leg.nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        // The sign-in window's session is new each time, so the user picks their Google account
        // rather than being signed in to one they left there.
        .append_pair("prompt", "select_account");
    Ok(url.into())
}

/// The Google account that signed in: its `sub`, which stays, and its address now.
pub struct Identity {
    pub subject: String,
    pub email: String,
    /// The Google Workspace domain the account belongs to, if any.
    pub hosted_domain: Option<String>,
}

impl Identity {
    /// Whether Google holds the address's mailbox itself, so that signing in to the Google
    /// account proves the mailbox as a mailed code would: Gmail, or a Workspace domain's own
    /// address. A Google account made on another address proves only that it once got mail.
    pub fn owns_mailbox(&self) -> bool {
        let domain = self.email.rsplit_once('@').map_or("", |(_, domain)| domain);
        matches!(domain, "gmail.com" | "googlemail.com")
            || self.hosted_domain.as_deref() == Some(domain)
    }
}

pub enum Refused {
    /// Google hasn't verified the account's address.
    Unverified,
    /// Anything else: the code, the token or Google itself. The reason is logged, never the
    /// code or the token.
    Failed,
}

#[derive(Deserialize)]
struct Answer {
    id_token: String,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    exp: i64,
    nonce: Option<String>,
    sub: String,
    email: Option<String>,
    #[serde(default)]
    email_verified: Value,
    hd: Option<String>,
}

/// Trades Google's code for its ID token at Google's token endpoint, and checks the token.
///
/// The token comes straight from Google over TLS, in answer to the client secret and the PKCE
/// verifier, so it is checked as OIDC Core 3.1.3.7 allows for that channel: issuer, audience,
/// expiry and nonce, without fetching Google's keys for its signature.
pub async fn exchange(
    http: &reqwest::Client,
    config: &Config,
    google: &Google,
    code: &str,
    leg: &Leg,
) -> Result<Identity, Refused> {
    let answer = http
        .post(&google.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &redirect_uri(config)),
            ("client_id", &google.client_id),
            ("client_secret", &google.client_secret.0),
            ("code_verifier", &leg.verifier),
        ])
        .send()
        .await;
    let answer = match answer {
        Ok(answer) if answer.status().is_success() => answer,
        Ok(answer) => {
            let status = answer.status().as_u16();
            tracing::warn!(status, "Google's token endpoint refused a sign-in's code");
            return Err(Refused::Failed);
        }
        Err(_) => {
            tracing::warn!("Google's token endpoint didn't answer");
            return Err(Refused::Failed);
        }
    };
    let Ok(Answer { id_token }) = answer.json().await else {
        tracing::warn!("Google's token endpoint answered without an ID token");
        return Err(Refused::Failed);
    };
    let Some(claims) = id_token
        .split('.')
        .nth(1)
        .and_then(|payload| URL_SAFE_NO_PAD.decode(payload).ok())
        .and_then(|payload| serde_json::from_slice::<Claims>(&payload).ok())
    else {
        tracing::warn!("Google's ID token can't be read");
        return Err(Refused::Failed);
    };
    // Google's tokens name it with or without the scheme.
    let issuer = google.issuer.as_str();
    let issued_by_google =
        claims.iss == issuer || Some(claims.iss.as_str()) == issuer.strip_prefix("https://");
    if !issued_by_google
        || claims.aud != google.client_id
        || claims.exp <= db::now()
        || claims.nonce.as_deref() != Some(leg.nonce.as_str())
    {
        tracing::warn!("Google's ID token isn't for this sign-in");
        return Err(Refused::Failed);
    }
    // Google has sent it as a string as well as a boolean.
    let verified = claims.email_verified == Value::Bool(true) || claims.email_verified == "true";
    let email = claims
        .email
        .as_deref()
        .and_then(super::normalize_email)
        .filter(|_| verified)
        .ok_or(Refused::Unverified)?;
    Ok(Identity {
        subject: claims.sub,
        email,
        hosted_domain: claims.hd.map(|domain| domain.to_lowercase()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(email: &str, hd: Option<&str>) -> Identity {
        Identity {
            subject: "1".into(),
            email: email.into(),
            hosted_domain: hd.map(str::to_owned),
        }
    }

    #[test]
    fn google_owns_gmail_and_a_workspace_domains_own_addresses_only() {
        assert!(identity("someone@gmail.com", None).owns_mailbox());
        assert!(identity("someone@googlemail.com", None).owns_mailbox());
        assert!(identity("someone@corp.example", Some("corp.example")).owns_mailbox());
        assert!(!identity("someone@corp.example", None).owns_mailbox());
        assert!(!identity("someone@corp.example", Some("other.example")).owns_mailbox());
        assert!(!identity("someone@gmail.com.example", None).owns_mailbox());
    }
}
