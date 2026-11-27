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
    /// The header, lowercase, that the proxy in front puts the client's address in, or none to
    /// count clients by the connection's.
    pub client_ip_header: Option<String>,
    /// Codes mailed to one client's sign-ins in an hour, across every address it asks for.
    pub codes_per_client_per_hour: i64,
    /// Codes the server mails in a day, under the mail account's quota.
    pub codes_per_day: i64,
    /// What one account may keep and send, so one signed-in account can't fill the database.
    pub sync_limits: crate::sync::Limits,
    /// `COUNTS_PASSWORD`, which `GET /counts` asks for as user `ilo`. Without it there's no page.
    pub counts_password: Option<Password>,
    /// `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, the server's own client at Google, for
    /// signing in with Google. Without them there's no Google road.
    pub google: Option<Google>,
    /// `GOOGLE_OFFERED`: the pages, discovery and `provider=google` offer the Google road. Off
    /// by default, so a client Google still has in testing, which only its listed test users can
    /// finish, is offered to no one. Off, a trip already at Google still comes back.
    pub google_offered: bool,
}

/// Google as the sign-in pages' other provider, with the server as its client.
#[derive(Clone, Debug)]
pub struct Google {
    pub client_id: String,
    pub client_secret: Password,
    /// Who signs Google's ID tokens, which the token's `iss` names.
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

impl Google {
    const ISSUER: &str = "https://accounts.google.com";

    /// Google's own endpoints, or with `GOOGLE_TEST_URL` a stand-in's: `/auth` and `/token`
    /// there, with that URL as the issuer.
    fn new(client_id: String, client_secret: String, test_url: Option<&str>) -> Self {
        let (issuer, authorization_endpoint, token_endpoint) = match test_url {
            Some(url) => {
                let url = url.trim_end_matches('/');
                (
                    url.to_owned(),
                    format!("{url}/auth"),
                    format!("{url}/token"),
                )
            }
            None => (
                Self::ISSUER.to_owned(),
                "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
                "https://oauth2.googleapis.com/token".to_owned(),
            ),
        };
        Self {
            client_id,
            client_secret: Password(client_secret),
            issuer,
            authorization_endpoint,
            token_endpoint,
        }
    }
}

/// A password from the environment, which `Debug` never prints.
#[derive(Clone)]
pub struct Password(pub String);

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(..)")
    }
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
        // Railway's edge puts the client's address in X-Real-IP.
        let client_ip_header = match (var("CLIENT_IP_HEADER"), var("RAILWAY_PUBLIC_DOMAIN")) {
            (Some(header), _) => Some(header),
            (None, Some(_)) => Some("x-real-ip".into()),
            (None, None) => None,
        };
        let client_ip_header = match client_ip_header {
            Some(header) => Some(
                axum::http::HeaderName::try_from(header.as_str())
                    .context("CLIENT_IP_HEADER is not a header name")?
                    .as_str()
                    .to_owned(),
            ),
            None => None,
        };
        let limit = |name: &str, default: i64| -> anyhow::Result<i64> {
            match var(name) {
                Some(value) => match value.parse() {
                    Ok(limit) if limit >= 1 => Ok(limit),
                    _ => bail!("{name} is not a number of codes, 1 or more"),
                },
                None => Ok(default),
            }
        };
        let count = |name: &str, default: i64| -> anyhow::Result<i64> {
            match var(name) {
                Some(value) => match value.parse() {
                    Ok(count) if count >= 1 => Ok(count),
                    _ => bail!("{name} is not a number, 1 or more"),
                },
                None => Ok(default),
            }
        };
        let test_url = var("GOOGLE_TEST_URL");
        if test_url.is_some() && !dev_mode {
            bail!("GOOGLE_TEST_URL is for tests, and is honoured only in DEV_MODE");
        }
        let google = match (var("GOOGLE_CLIENT_ID"), var("GOOGLE_CLIENT_SECRET")) {
            (Some(id), Some(secret)) => Some(Google::new(id, secret, test_url.as_deref())),
            (None, None) => None,
            _ => bail!("set both GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, or neither"),
        };
        let google_offered = match var("GOOGLE_OFFERED").as_deref() {
            None | Some("0" | "false") => false,
            Some("1" | "true") => true,
            Some(_) => bail!("GOOGLE_OFFERED is 1 or true to offer Google, else 0 or false"),
        };
        if google_offered && google.is_none() {
            bail!("GOOGLE_OFFERED needs GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET");
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
            client_ip_header,
            codes_per_client_per_hour: limit("CODES_PER_CLIENT_PER_HOUR", 10)?,
            // The hosted copy's mail account sends 1,000 a day, with room for new-sign-in notices.
            codes_per_day: limit("CODES_PER_DAY", 800)?,
            sync_limits: crate::sync::Limits {
                // Chromium's own limit on bookmarks is 100,000, and each other item is smaller.
                items: count("SYNC_ITEMS_PER_ACCOUNT", 200_000)?,
                bytes: count("SYNC_MB_PER_ACCOUNT", 256)? * 1024 * 1024,
                // A first sync sends its items 25 to a commit, one after another.
                commits_per_minute: count("SYNC_COMMITS_PER_MINUTE", 120)?,
            },
            counts_password: var("COUNTS_PASSWORD").map(Password),
            google,
            google_offered,
        })
    }

    /// The Google client, while the server offers its road.
    pub fn offered_google(&self) -> Option<&Google> {
        self.google.as_ref().filter(|_| self.google_offered)
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
    fn the_counts_password_is_never_printed() {
        let set = config(&[("DEV_MODE", "1"), ("COUNTS_PASSWORD", "secret-word")]).unwrap();
        assert_eq!(
            set.counts_password
                .as_ref()
                .map(|password| password.0.as_str()),
            Some("secret-word")
        );
        assert!(!format!("{set:?}").contains("secret-word"));
        let unset = config(&[("DEV_MODE", "1")]).unwrap();
        assert!(unset.counts_password.is_none());
    }

    #[test]
    fn google_needs_its_id_and_secret_together_and_never_prints_the_secret() {
        let set = production(&[
            ("SMTP_URL", "smtps://mail.example.org"),
            ("GOOGLE_CLIENT_ID", "client.apps.googleusercontent.com"),
            ("GOOGLE_CLIENT_SECRET", "secret-word"),
        ])
        .unwrap();
        let google = set.google.as_ref().unwrap();
        assert_eq!(google.client_id, "client.apps.googleusercontent.com");
        assert_eq!(google.client_secret.0, "secret-word");
        assert_eq!(google.issuer, "https://accounts.google.com");
        assert!(!format!("{set:?}").contains("secret-word"));
        assert!(config(&[("DEV_MODE", "1")]).unwrap().google.is_none());
        for one in ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"] {
            let error = config(&[("DEV_MODE", "1"), (one, "x")]).unwrap_err();
            assert!(error.to_string().contains("neither"), "{one}");
        }
    }

    #[test]
    fn a_stand_in_google_is_for_dev_mode_only() {
        let google = [
            ("GOOGLE_CLIENT_ID", "id"),
            ("GOOGLE_CLIENT_SECRET", "secret"),
            ("GOOGLE_TEST_URL", "http://127.0.0.1:9000/"),
        ];
        let dev = config(&[&google[..], &[("DEV_MODE", "1")]].concat()).unwrap();
        let google_config = dev.google.unwrap();
        assert_eq!(google_config.issuer, "http://127.0.0.1:9000");
        assert_eq!(google_config.token_endpoint, "http://127.0.0.1:9000/token");
        let error = production(&[&google[..], &[("SMTP_URL", "smtps://m.example.org")]].concat())
            .unwrap_err();
        assert!(error.to_string().contains("GOOGLE_TEST_URL"));
    }

    #[test]
    fn google_is_offered_only_when_the_server_says_so() {
        let google = [
            ("DEV_MODE", "1"),
            ("GOOGLE_CLIENT_ID", "id"),
            ("GOOGLE_CLIENT_SECRET", "secret"),
        ];
        let set = config(&google).unwrap();
        assert!(
            set.google.is_some() && set.offered_google().is_none(),
            "off by default"
        );
        for (value, offered) in [("1", true), ("true", true), ("0", false), ("false", false)] {
            let set = config(&[&google[..], &[("GOOGLE_OFFERED", value)]].concat()).unwrap();
            assert_eq!(set.offered_google().is_some(), offered, "{value}");
        }
        let error = config(&[&google[..], &[("GOOGLE_OFFERED", "yes")]].concat()).unwrap_err();
        assert!(error.to_string().contains("GOOGLE_OFFERED"));
        let error = config(&[("DEV_MODE", "1"), ("GOOGLE_OFFERED", "1")]).unwrap_err();
        assert!(error.to_string().contains("GOOGLE_CLIENT_ID"));
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
    fn clients_are_counted_by_the_connection_or_the_named_header() {
        let default = config(&[("DEV_MODE", "1")]).unwrap();
        assert_eq!(default.client_ip_header, None);
        assert_eq!(
            (default.codes_per_client_per_hour, default.codes_per_day),
            (10, 800)
        );
        let named = config(&[("DEV_MODE", "1"), ("CLIENT_IP_HEADER", "X-Forwarded-For")]).unwrap();
        assert_eq!(named.client_ip_header.as_deref(), Some("x-forwarded-for"));
        let error = config(&[("DEV_MODE", "1"), ("CLIENT_IP_HEADER", "not a header")]).unwrap_err();
        assert!(error.to_string().contains("CLIENT_IP_HEADER"));
    }

    #[test]
    fn on_railway_clients_are_counted_by_x_real_ip() {
        let railway = config(&[
            ("DEV_MODE", "1"),
            ("RAILWAY_PUBLIC_DOMAIN", "ilo.up.railway.app"),
        ])
        .unwrap();
        assert_eq!(railway.client_ip_header.as_deref(), Some("x-real-ip"));
    }

    #[test]
    fn code_limits_are_one_or_more() {
        let fifty = config(&[("DEV_MODE", "1"), ("CODES_PER_DAY", "50")]).unwrap();
        assert_eq!(fifty.codes_per_day, 50);
        for value in ["0", "-3", "many"] {
            let error = config(&[("DEV_MODE", "1"), ("CODES_PER_CLIENT_PER_HOUR", value)]);
            assert!(
                error
                    .unwrap_err()
                    .to_string()
                    .contains("CODES_PER_CLIENT_PER_HOUR"),
                "{value}"
            );
        }
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
