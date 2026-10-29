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
    pub smtp_url: Option<String>,
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
        let smtp_url = var("SMTP_URL");
        if smtp_url.is_none() && !dev_mode {
            bail!("SMTP_URL is needed to send sign-in codes; set DEV_MODE=1 to log them instead");
        }
        let mail_from = var("MAIL_FROM");
        if smtp_url.is_some() && mail_from.is_none() {
            bail!("MAIL_FROM is needed with SMTP_URL");
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
        Ok(Self {
            host: var("HOST").unwrap_or_else(|| "0.0.0.0".into()),
            port,
            database_url: var("DATABASE_URL")
                .unwrap_or_else(|| "sqlite:ilo-server.db?mode=rwc".into()),
            public_url,
            dev_mode,
            smtp_url,
            mail_from,
            redirect_uris: var("OIDC_REDIRECT_URIS")
                .map(|uris| uris.split(',').map(|uri| uri.trim().to_owned()).collect())
                .unwrap_or_default(),
            client_ip_header,
            codes_per_client_per_hour: limit("CODES_PER_CLIENT_PER_HOUR", 10)?,
            // The hosted copy's mail account sends 1,000 a day, with room for new-sign-in notices.
            codes_per_day: limit("CODES_PER_DAY", 800)?,
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
        assert!(config.smtp_url.is_none());
    }

    #[test]
    fn production_needs_a_mailer() {
        let error = config(&[("PUBLIC_URL", "https://sync.example.org")]).unwrap_err();
        assert!(error.to_string().contains("SMTP_URL"));
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
