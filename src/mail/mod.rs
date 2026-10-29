//! Sends sign-in codes and new-sign-in notices: by SMTP, by Cloudflare Email Service's send API,
//! or to the log in dev mode. A code goes as text and as a page with the wordmark (code.html).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::Deserialize;
use serde_json::json;

use crate::config::{Config, Transport};

/// Where Cloudflare's API is.
pub const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";

/// What an HTML mail shows by `cid:` URL, inline, since Gmail and Outlook show no SVG: the
/// wordmark (accounts/pages.rs) at twice its 40×28 size, Ink and Paper, drawn by headless Chromium.
const IMAGES: [(&str, &str, &[u8]); 2] = [
    ("wordmark", "ilo.png", include_bytes!("wordmark.png")),
    (
        "wordmark-dark",
        "ilo-dark.png",
        include_bytes!("wordmark-dark.png"),
    ),
];

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
    pub html: Option<String>,
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

    /// Mails a code, whose page names the server by `host`, PUBLIC_URL's.
    pub async fn send_code(&self, to: &str, code: &str, host: &str) -> anyhow::Result<()> {
        self.send(
            to,
            format!("{code} is your ilo sign-in code"),
            format!(
                "Your ilo sign-in code is {code}.\n\n\
                 It works for 10 minutes. If you didn't try to sign in, \
                 you can ignore this mail.\n"
            ),
            Some(code_page(code, host)),
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
            None,
        )
        .await
    }

    async fn send(
        &self,
        to: &str,
        subject: String,
        body: String,
        html: Option<String>,
    ) -> anyhow::Result<()> {
        match self {
            Self::Smtp(smtp) => {
                let message = message(&smtp.from, to, subject, body, html)?;
                smtp.transport
                    .send(message)
                    .await
                    .context("the SMTP server refused the mail")?;
            }
            Self::Cloudflare(api) => api.send(to, &subject, &body, html).await?,
            Self::Log => tracing::info!(to, subject, body, "mail (DEV_MODE, not sent)"),
            Self::Recording(sent) => sent.lock().unwrap().push(Mail {
                to: to.to_owned(),
                subject,
                body,
                html,
            }),
        }
        Ok(())
    }
}

fn code_page(code: &str, host: &str) -> String {
    // Mail apps link a host they find in text, and the page has no links, so each dot gets an
    // element of its own.
    let host = host.replace('.', "<span>.</span>");
    include_str!("code.html")
        .replace("{code}", code)
        .replace("{host}", &host)
}

/// A mail for SMTP: the text alone, or the text or the HTML with its images, as the reader's app
/// prefers.
fn message(
    from: &Mailbox,
    to: &str,
    subject: String,
    body: String,
    html: Option<String>,
) -> anyhow::Result<Message> {
    let builder = Message::builder()
        .from(from.clone())
        .to(to.parse().context("not an email address")?)
        .subject(subject);
    let Some(html) = html else {
        return Ok(builder.body(body)?);
    };
    let png = ContentType::parse("image/png").expect("a MIME type");
    let page = IMAGES.iter().fold(
        MultiPart::related().singlepart(SinglePart::html(html)),
        |page, (id, name, image)| {
            page.singlepart(
                Attachment::new_inline_with_name((*id).into(), (*name).into())
                    .body(image.to_vec(), png.clone()),
            )
        },
    );
    Ok(builder.multipart(
        MultiPart::alternative()
            .singlepart(SinglePart::plain(body))
            .multipart(page),
    )?)
}

impl Cloudflare {
    async fn send(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        html: Option<String>,
    ) -> anyhow::Result<()> {
        let to: lettre::Address = to.parse().context("not an email address")?;
        let from = match &self.from.name {
            Some(name) => json!({ "address": self.from.email.to_string(), "name": name }),
            None => json!(self.from.email.to_string()),
        };
        let mut mail =
            json!({ "to": to.to_string(), "from": from, "subject": subject, "text": text });
        if let Some(html) = html {
            mail["html"] = html.into();
            mail["attachments"] = (IMAGES.iter())
                .map(|(id, name, image)| {
                    json!({
                        "content": BASE64.encode(image), "content_id": id, "disposition": "inline",
                        "filename": name, "type": "image/png",
                    })
                })
                .collect();
        }
        let response = self
            .client
            .post(&self.url)
            .bearer_auth(&self.token)
            .json(&mail)
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
            .send_code("someone@example.org", "123456", "sync.example.org")
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
        assert!(body["html"].as_str().unwrap().contains(">123456<"));
        let attachments = body["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 2);
        for (attachment, id) in attachments.iter().zip(["wordmark", "wordmark-dark"]) {
            assert_eq!(attachment["content_id"], id);
            assert_eq!(attachment["disposition"], "inline");
            assert_eq!(attachment["type"], "image/png");
            let png = BASE64
                .decode(attachment["content"].as_str().unwrap())
                .unwrap();
            assert!(png.starts_with(b"\x89PNG"));
        }
    }

    #[test]
    fn the_code_page_shows_the_code_and_host_and_links_nowhere() {
        let page = code_page("012345", "sync.example.org");
        // One string, so a copy gives the digits alone.
        assert!(page.contains(">012345<"));
        assert!(page.contains("sync<span>.</span>example<span>.</span>org"));
        assert!(page.contains(r#"src="cid:wordmark""#) && page.contains(r#"alt="ilo""#));
        for absent in ["{code}", "{host}", "<a ", "href", "http", "@import", "url("] {
            assert!(!page.contains(absent), "the page has {absent}");
        }
    }

    #[test]
    fn smtp_sends_text_or_the_page_with_its_images() {
        let from = "ilo <sign-in@example.org>".parse().unwrap();
        let page = code_page("123456", "sync.example.org");
        let mail = message(
            &from,
            "someone@example.org",
            "s".into(),
            "text".into(),
            Some(page),
        );
        let mail = String::from_utf8(mail.unwrap().formatted()).unwrap();
        let parts: Vec<&str> = [
            "multipart/alternative",
            "text/plain",
            "multipart/related",
            "text/html",
        ]
        .into_iter()
        .chain(["Content-ID: <wordmark>", "Content-ID: <wordmark-dark>"])
        .collect();
        let mut rest = mail.as_str();
        for part in parts {
            let at = rest
                .find(part)
                .unwrap_or_else(|| panic!("no {part} in order"));
            rest = &rest[at..];
        }
        assert_eq!(mail.matches("Content-Disposition: inline").count(), 2);
        let mail = message(
            &from,
            "someone@example.org",
            "s".into(),
            "text".into(),
            None,
        );
        let mail = String::from_utf8(mail.unwrap().formatted()).unwrap();
        assert!(!mail.contains("multipart"));
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
            .send_code("someone@example.org", "123456", "sync.example.org")
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
                .send_code("someone@example.org", "1", "sync.example.org")
                .await
                .is_err()
        );
        let (url, _) = api(StatusCode::BAD_GATEWAY, json!("not the API")).await;
        let error = mailer(&url)
            .send_code("someone@example.org", "1", "sync.example.org")
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
            .send_code("someone@example.org", "1", "sync.example.org")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("can't reach"), "{error}");
        assert!(!error.to_string().contains("secret-token"), "{error}");
    }
}
