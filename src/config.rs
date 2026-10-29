//! Settings, read only from the environment.

use anyhow::{Context, bail};
use url::Url;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    /// Where clients reach the server: the OIDC issuer and the passkeys' origin.
    pub public_url: Url,
    /// Sign-in codes go to the log instead of by mail, and plain http is allowed.
    pub dev_mode: bool,
    /// How mail goes out: none in dev mode, where codes go to the log.
    pub mail: Option<Transport>,
    pub mail_from: Option<String>,
    /// Redirect URIs allowed besides loopback addresses and `/signed-in`.
    pub redirect_uris: Vec<String>,
}

/// One way to send mail, which the server sets up at start.
#[derive(Clone)]
pub enum Transport {
    /// `SMTP_URL`, for self-hosters' mail accounts.
    Smtp(String),
    /// Cloudflare Email Service's send API, over HTTPS, for hosts that block outbound SMTP, as
    /// Railway does below its Pro plan.
    Cloudflare { account_id: String, token: String },
}

// The URL and the token hold passwords.
impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Smtp(_) => f.write_str("Smtp(..)"),
            Self::Cloudflare { account_id, .. } => {
                write!(f, "Cloudflare {{ account_id: {account_id:?}, .. }}")
            }
        }
    }
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
    }

    pub fn from_lookup(var: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let port = match var("PORT") {
            Some(port) => port.parse().context("PORT is not a port number")?,
            None => 8080,
        };
        let dev_mode = matches!(var("DEV_MODE").as_deref(), Some("1" | "true"));
        // Railway names the service's public domain, so a template needs no PUBLIC_URL.
        let public_url = match (var("PUBLIC_URL"), var("RAILWAY_PUBLIC_DOMAIN")) {
            (Some(url), _) => url,
            (None, Some(domain)) => format!("https://{domain}"),
            (None, None) => format!("http://localhost:{port}"),
        };
        let public_url =
            Url::parse(public_url.trim_end_matches('/')).context("PUBLIC_URL is not a URL")?;
        if public_url.host_str().is_none() {
            bail!("PUBLIC_URL has no host");
        }
        let local = matches!(
            public_url.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]")
        );
        if public_url.scheme() != "https" && !dev_mode && !local {
            bail!("PUBLIC_URL must be https outside DEV_MODE");
        }
        let mail = match (var("SMTP_URL"), var("MAIL_API")) {
            (Some(_), Some(_)) => bail!("set SMTP_URL or MAIL_API, not both"),
            (Some(url), None) => Some(Transport::Smtp(url)),
            (None, Some(api)) if api == "cloudflare" => Some(Transport::Cloudflare {
                account_id: var("CLOUDFLARE_ACCOUNT_ID")
                    .context("CLOUDFLARE_ACCOUNT_ID is needed with MAIL_API=cloudflare")?,
                token: var("CLOUDFLARE_API_TOKEN")
                    .context("CLOUDFLARE_API_TOKEN is needed with MAIL_API=cloudflare")?,
            }),
            (None, Some(api)) => bail!("MAIL_API is {api:?}; the one it knows is cloudflare"),
            (None, None) if dev_mode => None,
            (None, None) => bail!(
                "SMTP_URL or MAIL_API is needed to send sign-in codes; set DEV_MODE=1 to log them instead"
            ),
        };
        let mail_from = var("MAIL_FROM");
        if mail.is_some() && mail_from.is_none() {
            bail!("MAIL_FROM is needed to send mail");
        }
        Ok(Self {
            host: var("HOST").unwrap_or_else(|| "0.0.0.0".into()),
            port,
            database_url: var("DATABASE_URL")
                .unwrap_or_else(|| "sqlite:ilo-server.db?mode=rwc".into()),
            public_url,
            dev_mode,
            mail,
            mail_from,
            redirect_uris: var("OIDC_REDIRECT_URIS")
                .map(|uris| uris.split(',').map(|uri| uri.trim().to_owned()).collect())
                .unwrap_or_default(),
        })
    }

    /// The issuer, without a trailing slash, as OIDC compares it byte for byte.
    pub fn issuer(&self) -> String {
        self.public_url.as_str().trim_end_matches('/').to_owned()
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.issuer())
    }

    pub fn secure_cookies(&self) -> bool {
        self.public_url.scheme() == "https"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(vars: &[(&str, &str)]) -> anyhow::Result<Config> {
        Config::from_lookup(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        })
    }

    #[test]
    fn dev_mode_needs_nothing_else() {
        let config = config(&[("DEV_MODE", "1")]).unwrap();
        assert_eq!(config.issuer(), "http://localhost:8080");
        assert!(config.mail.is_none());
    }

    #[test]
    fn production_needs_a_mailer() {
        let error = config(&[("PUBLIC_URL", "https://sync.example.org")]).unwrap_err();
        assert!(error.to_string().contains("SMTP_URL or MAIL_API"));
    }

    const PRODUCTION: [(&str, &str); 2] = [
        ("PUBLIC_URL", "https://sync.example.org"),
        ("MAIL_FROM", "ilo <sync@example.org>"),
    ];

    fn production(vars: &[(&str, &str)]) -> anyhow::Result<Config> {
        config(&[&PRODUCTION[..], vars].concat())
    }

    #[test]
    fn cloudflare_api_is_a_mailer() {
        let config = production(&[
            ("MAIL_API", "cloudflare"),
            ("CLOUDFLARE_ACCOUNT_ID", "account"),
            ("CLOUDFLARE_API_TOKEN", "secret-token"),
        ])
        .unwrap();
        assert!(matches!(
            &config.mail,
            Some(Transport::Cloudflare { account_id, token })
                if account_id == "account" && token == "secret-token"
        ));
        assert!(!format!("{config:?}").contains("secret-token"));
    }

    #[test]
    fn cloudflare_api_needs_its_account_and_token() {
        let error =
            production(&[("MAIL_API", "cloudflare"), ("CLOUDFLARE_API_TOKEN", "t")]).unwrap_err();
        assert!(error.to_string().contains("CLOUDFLARE_ACCOUNT_ID"));
        let error =
            production(&[("MAIL_API", "cloudflare"), ("CLOUDFLARE_ACCOUNT_ID", "a")]).unwrap_err();
        assert!(error.to_string().contains("CLOUDFLARE_API_TOKEN"));
    }

    #[test]
    fn one_mailer_only() {
        let error = production(&[
            ("SMTP_URL", "smtps://mail.example.org"),
            ("MAIL_API", "cloudflare"),
            ("CLOUDFLARE_ACCOUNT_ID", "a"),
            ("CLOUDFLARE_API_TOKEN", "t"),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("not both"));
        let error = production(&[("MAIL_API", "resend")]).unwrap_err();
        assert!(error.to_string().contains("cloudflare"));
    }

    #[test]
    fn a_mailer_needs_a_sender() {
        let error = config(&[
            ("PUBLIC_URL", "https://sync.example.org"),
            ("SMTP_URL", "smtps://mail.example.org"),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("MAIL_FROM"));
    }

    #[test]
    fn production_needs_https() {
        let error = config(&[
            ("PUBLIC_URL", "http://sync.example.org"),
            ("SMTP_URL", "smtps://mail.example.org"),
            ("MAIL_FROM", "ilo <sync@example.org>"),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("https"));
    }

    #[test]
    fn railway_domain_is_the_default_public_url() {
        let config = config(&[
            ("DEV_MODE", "1"),
            ("RAILWAY_PUBLIC_DOMAIN", "ilo.up.railway.app"),
        ])
        .unwrap();
        assert_eq!(config.issuer(), "https://ilo.up.railway.app");
    }
}
