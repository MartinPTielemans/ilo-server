//! Sends sign-in codes and new-sign-in notices: by SMTP, or to the log in dev mode.

use std::sync::{Arc, Mutex};

use anyhow::Context;
use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::Config;

#[derive(Clone)]
pub enum Mailer {
    Smtp(Box<Smtp>),
    Log,
    /// Keeps what it's given, for tests.
    Recording(Arc<Mutex<Vec<Mail>>>),
}

#[derive(Clone)]
pub struct Smtp {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

#[derive(Clone, Debug)]
pub struct Mail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

impl Mailer {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        match (&config.smtp_url, &config.mail_from) {
            (Some(url), Some(from)) => Ok(Self::Smtp(Box::new(Smtp {
                transport: AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
                    .context("SMTP_URL is not an SMTP URL")?
                    .build(),
                from: from.parse().context("MAIL_FROM is not an address")?,
            }))),
            _ => Ok(Self::Log),
        }
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
