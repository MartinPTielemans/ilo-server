//! Sends sign-in codes and new-sign-in notices: by SMTP, by Cloudflare Email Service's send API,
//! or to the log in dev mode.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::Deserialize;
use serde_json::json;

use crate::config::{Config, Transport};

/// Where Cloudflare's API is.
pub const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";

#[derive(Clone)]
pub enum Mailer {
    Smtp(Box<Smtp>),
    Cloudflare(Box<Cloudflare>),
    Log,
    /// Keeps what it's given, for tests.
    Recording(Arc<Mutex<Vec<Mail>>>),
}

#[derive(Clone)]
pub struct Smtp {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

/// Cloudflare Email Service's send API, for one account.
#[derive(Clone)]
pub struct Cloudflare {
    client: reqwest::Client,
    url: String,
    token: String,
    from: Mailbox,
}

/// What the API answers, as far as the server reads it.
#[derive(Default, Deserialize)]
struct Answer {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: Option<Sent>,
}

#[derive(Deserialize)]
struct ApiError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct Sent {
    #[serde(default)]
    permanent_bounces: Vec<String>,
    #[serde(default)]
    suppressed_recipients: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Mail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

impl Mailer {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let (Some(transport), Some(from)) = (&config.mail, &config.mail_from) else {
            return Ok(Self::Log);
        };
        let from: Mailbox = from.parse().context("MAIL_FROM is not an address")?;
        match transport {
            Transport::Smtp(url) => Ok(Self::Smtp(Box::new(Smtp {
                transport: AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
                    .context("SMTP_URL is not an SMTP URL")?
                    .build(),
                from,
            }))),
            Transport::Cloudflare { account_id, token } => {
                Self::cloudflare(CLOUDFLARE_API, account_id, token, from)
            }
        }
    }

    /// Sends through Cloudflare's send API at `api`, which tests point at their own server.
    pub fn cloudflare(
        api: &str,
        account_id: &str,
        token: &str,
        from: Mailbox,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            // A sign-in waits on the answer, so an API that doesn't answer fails it, as SMTP does.
            .timeout(Duration::from_secs(30))
            .build()
            .context("can't make an HTTPS client")?;
        Ok(Self::Cloudflare(Box::new(Cloudflare {
            client,
            url: format!("{api}/accounts/{account_id}/email/sending/send"),
            token: token.to_owned(),
            from,
        })))
    }

    pub fn recording() -> (Self, Arc<Mutex<Vec<Mail>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (Self::Recording(sent.clone()), sent)
    }

    pub async fn send_code(&self, to: &str, code: &str) -> anyhow::Result<()> {
        self.send(
            to,
            format!("{code} is your ilo sign-in code"),
            format!(
                "Your ilo sign-in code is {code}.\n\n\
                 It works for 10 minutes. If you didn't try to sign in, \
                 you can ignore this mail.\n"
            ),
        )
        .await
    }

    /// Tells an account that a device it didn't have before signed in. The
    /// mail's date says when.
    pub async fn send_new_sign_in(&self, to: &str, device: &str) -> anyhow::Result<()> {
        // The name is the device's own choice, so it can't add lines to the mail.
        let device: String = device
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        self.send(
            to,
            "A new device signed in to your ilo account".into(),
            format!(
                "A device named \"{device}\" just signed in to your ilo account.\n\n\
                 If it wasn't you, remove the device in ilo under Settings, Account, \
                 and don't approve a request to add a device that you didn't start. \
                 Whoever signed in got a code mailed to this address, so check who \
                 else can read your email.\n"
            ),
        )
        .await
    }

    async fn send(&self, to: &str, subject: String, body: String) -> anyhow::Result<()> {
        match self {
            Self::Smtp(smtp) => {
                let message = Message::builder()
                    .from(smtp.from.clone())
                    .to(to.parse().context("not an email address")?)
                    .subject(subject)
                    .body(body)?;
                smtp.transport
                    .send(message)
                    .await
                    .context("the SMTP server refused the mail")?;
            }
            Self::Cloudflare(api) => api.send(to, &subject, &body).await?,
            Self::Log => tracing::info!(to, subject, body, "mail (DEV_MODE, not sent)"),
            Self::Recording(sent) => sent.lock().unwrap().push(Mail {
                to: to.to_owned(),
                subject,
                body,
            }),
        }
        Ok(())
    }
}

impl Cloudflare {
    async fn send(&self, to: &str, subject: &str, text: &str) -> anyhow::Result<()> {
        let to: lettre::Address = to.parse().context("not an email address")?;
        let from = match &self.from.name {
            Some(name) => json!({ "address": self.from.email.to_string(), "name": name }),
            None => json!(self.from.email.to_string()),
        };
        let response = self
            .client
            .post(&self.url)
            .bearer_auth(&self.token)
            .json(&json!({ "to": to.to_string(), "from": from, "subject": subject, "text": text }))
            .send()
            .await
            .map_err(|error| {
                let error = anyhow::Error::from(error.without_url());
                anyhow!("can't reach Cloudflare's send API: {error:#}")
            })?;
        let status = response.status();
        let answer: Answer = response.json().await.unwrap_or_default();
        if !status.is_success() || !answer.success {
            let errors: Vec<String> = (answer.errors.iter())
                .map(|error| format!("{} {}", error.code, error.message))
                .collect();
            bail!(
                "Cloudflare's send API refused the mail: {status} ({})",
                errors.join(", ")
            );
        }
        // Sent as far as the server can tell, as an SMTP server's accepting a mail it bounces
        // later is, so the sign-in page answers alike for every address.
        if let Some(sent) = answer.result
            && !(sent.permanent_bounces.is_empty() && sent.suppressed_recipients.is_empty())
        {
            tracing::warn!("Cloudflare's send API bounced a mail or dropped it as suppressed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::extract::Path;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::Value;

    type Seen = Arc<Mutex<Vec<(String, String, Value)>>>;

    /// An API on a free port that answers every send with `status` and `answer`, and keeps each
    /// request's account, Authorization header and body.
    async fn api(status: StatusCode, answer: Value) -> (String, Seen) {
        let seen = Seen::default();
        let kept = seen.clone();
        let app = Router::new().route(
            "/accounts/{account}/email/sending/send",
            post(
                move |Path(account): Path<String>, headers: HeaderMap, Json(body): Json<Value>| {
                    let authorization = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    kept.lock().unwrap().push((account, authorization, body));
                    async move { (status, Json(answer)) }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    fn mailer(api: &str) -> Mailer {
        let from = "ilo <sign-in@example.org>".parse().unwrap();
        Mailer::cloudflare(api, "account-id", "secret-token", from).unwrap()
    }

    #[tokio::test]
    async fn sends_a_code_through_the_account() {
        let sent = json!({
            "success": true, "errors": [], "messages": [],
            "result": { "delivered": ["someone@example.org"], "permanent_bounces": [], "queued": [] }
        });
        let (url, seen) = api(StatusCode::OK, sent).await;
        mailer(&url)
            .send_code("someone@example.org", "123456")
            .await
            .unwrap();
        let seen = seen.lock().unwrap();
        let [(account, authorization, body)] = &seen[..] else {
            panic!("the API got {} requests", seen.len());
        };
        assert_eq!(account, "account-id");
        assert_eq!(authorization, "Bearer secret-token");
        assert_eq!(body["to"], "someone@example.org");
        assert_eq!(
            body["from"],
            json!({ "address": "sign-in@example.org", "name": "ilo" })
        );
        assert_eq!(body["subject"], "123456 is your ilo sign-in code");
        assert!(
            body["text"]
                .as_str()
                .unwrap()
                .contains("Your ilo sign-in code is 123456.")
        );
    }

    #[tokio::test]
    async fn a_refusal_names_its_status_and_not_the_token() {
        let refused = json!({
            "success": false,
            "errors": [{ "code": 10102, "message": "email.sending.error.authentication.forbidden" }],
            "messages": [], "result": null
        });
        let (url, _) = api(StatusCode::FORBIDDEN, refused).await;
        let error = mailer(&url)
            .send_code("someone@example.org", "123456")
            .await
            .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("403 Forbidden"), "{error}");
        assert!(error.contains("10102"), "{error}");
        assert!(!error.contains("secret-token"), "{error}");
    }

    #[tokio::test]
    async fn an_answer_that_isnt_a_success_fails() {
        let (url, _) = api(StatusCode::OK, json!({ "success": false, "errors": [] })).await;
        assert!(
            mailer(&url)
                .send_code("someone@example.org", "1")
                .await
                .is_err()
        );
        let (url, _) = api(StatusCode::BAD_GATEWAY, json!("not the API")).await;
        let error = mailer(&url)
            .send_code("someone@example.org", "1")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("502"), "{error}");
    }

    #[tokio::test]
    async fn an_api_it_cant_reach_fails() {
        // A port nothing listens on, once its listener is gone.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let error = mailer(&url)
            .send_code("someone@example.org", "1")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("can't reach"), "{error}");
        assert!(!error.to_string().contains("secret-token"), "{error}");
    }
}
