//! Sends sign-in codes: by SMTP, or to the log in dev mode.

use std::sync::{Arc, Mutex};

use anyhow::Context;
use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::Config;

#[derive(Clone)]
pub enum Mailer {
    Smtp {
        transport: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
    },
    Log,
    /// Keeps what it's given, for tests.
    Recording(Arc<Mutex<Vec<Mail>>>),
}

#[derive(Clone, Debug)]
pub struct Mail {
    pub to: String,
    pub code: String,
}

impl Mailer {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        match (&config.smtp_url, &config.mail_from) {
            (Some(url), Some(from)) => Ok(Self::Smtp {
                transport: AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
                    .context("SMTP_URL is not an SMTP URL")?
                    .build(),
                from: from.parse().context("MAIL_FROM is not an address")?,
            }),
            _ => Ok(Self::Log),
        }
    }

    pub fn recording() -> (Self, Arc<Mutex<Vec<Mail>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (Self::Recording(sent.clone()), sent)
    }

    pub async fn send_code(&self, to: &str, code: &str) -> anyhow::Result<()> {
        match self {
            Self::Smtp { transport, from } => {
                let message = Message::builder()
                    .from(from.clone())
                    .to(to.parse().context("not an email address")?)
                    .subject(format!("{code} is your ilo sign-in code"))
                    .body(format!(
                        "Your ilo sign-in code is {code}.\n\n\
                         It works for 10 minutes. If you didn't try to sign in, \
                         you can ignore this mail.\n"
                    ))?;
                transport
                    .send(message)
                    .await
                    .context("the SMTP server refused the mail")?;
            }
            Self::Log => tracing::info!(to, code, "sign-in code (DEV_MODE, not mailed)"),
            Self::Recording(sent) => sent.lock().unwrap().push(Mail {
                to: to.to_owned(),
                code: code.to_owned(),
            }),
        }
        Ok(())
    }
}
