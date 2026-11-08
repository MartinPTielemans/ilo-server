//! Whether an address's domain can get mail, asked before a sign-in code goes to it. A code mailed
//! to a domain with nowhere to deliver it bounces, and the mail service counts each bounce against
//! the server's sending reputation, which at a few mails a day a single typo can sink.

use std::time::Duration;

use anyhow::Context;
use hickory_resolver::TokioResolver;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::RData;

/// The longest the resolver keeps an answer: a sign-in's resends ask DNS once, and a domain whose
/// records were just set up takes mail within minutes.
const KEPT: Duration = Duration::from_secs(5 * 60);
/// The longest a sign-in waits on DNS before it mails anyway.
const WAIT: Duration = Duration::from_secs(5);

pub enum Domains {
    Dns(Box<TokioResolver>),
    /// Every domain takes mail but these: for a server that mails no one, and for tests.
    Except(Vec<String>),
}

impl Domains {
    /// Asks the resolvers the system names, as the server's own mail would be looked up.
    pub fn system() -> anyhow::Result<Self> {
        let mut builder =
            TokioResolver::builder_tokio().context("can't read the system's DNS settings")?;
        let options = builder.options_mut();
        options.positive_max_ttl = Some(KEPT);
        options.negative_max_ttl = Some(KEPT);
        Ok(Self::Dns(Box::new(
            builder.build().context("can't make a DNS resolver")?,
        )))
    }

    pub fn except(domains: &[&str]) -> Self {
        Self::Except(domains.iter().map(|domain| domain.to_string()).collect())
    }

    /// Whether `domain` can get mail. DNS that doesn't answer, or answers with an error that isn't
    /// "no such records", counts as yes: a sign-in shouldn't fail on the resolver's trouble.
    pub async fn take_mail(&self, domain: &str) -> bool {
        let resolver = match self {
            Self::Dns(resolver) => resolver,
            Self::Except(domains) => return !domains.iter().any(|listed| listed == domain),
        };
        // Fully qualified, so the resolver's search domains can't make a typo resolve.
        let name = format!("{}.", domain.trim_end_matches('.'));
        let looked_up = async {
            match mail_hosts(resolver.mx_lookup(name.as_str()).await) {
                Found::None => Found::from(
                    resolver
                        .lookup_ip(name.as_str())
                        .await
                        .map(|ips| ips.iter().next().is_some()),
                ),
                found => found,
            }
        };
        match tokio::time::timeout(WAIT, looked_up).await {
            Ok(Found::No | Found::None) => false,
            Ok(Found::Yes | Found::Unknown) => true,
            Err(_) => {
                tracing::warn!("DNS took too long to say whether an address's domain takes mail");
                true
            }
        }
    }
}

/// What DNS said of a domain's mail.
#[derive(Debug, PartialEq)]
enum Found {
    Yes,
    /// It takes no mail: it doesn't exist, or it says so with a null MX (RFC 7505).
    No,
    /// No records of the kind asked for, though the domain exists.
    None,
    Unknown,
}

impl From<Result<bool, NetError>> for Found {
    fn from(answer: Result<bool, NetError>) -> Self {
        match answer {
            Ok(true) => Self::Yes,
            Ok(false) => Self::None,
            Err(error) if error.is_nx_domain() => Self::No,
            Err(error) if error.is_no_records_found() => Self::None,
            Err(error) => {
                tracing::warn!(%error, "DNS couldn't say whether an address's domain takes mail");
                Self::Unknown
            }
        }
    }
}

/// An MX answer: any host but the root takes mail, and the root alone is a null MX.
fn mail_hosts(answer: Result<Lookup, NetError>) -> Found {
    let hosts = answer.map(|lookup| {
        lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::MX(mx) => Some(mx.exchange.is_root()),
                _ => None,
            })
            .collect::<Vec<bool>>()
    });
    match hosts {
        Ok(hosts) if hosts.iter().any(|null| !null) => Found::Yes,
        Ok(hosts) if !hosts.is_empty() => Found::No,
        Ok(_) => Found::None,
        Err(error) => Found::from(Err(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The domains RFC 2606 and RFC 7505 make sure of: .invalid names no domain, and example.org
    // says with a null MX that it takes no mail.
    #[tokio::test]
    #[ignore = "asks the network's DNS"]
    async fn the_system_resolver_tells_domains_that_take_mail_from_those_that_dont() {
        let domains = Domains::system().unwrap();
        assert!(domains.take_mail("gmail.com").await);
        assert!(!domains.take_mail("example.org").await);
        assert!(!domains.take_mail("gmial.invalid").await);
    }

    fn mx(hosts: &[&str]) -> Result<Lookup, NetError> {
        use hickory_resolver::proto::op::Query;
        use hickory_resolver::proto::rr::rdata::MX;
        use hickory_resolver::proto::rr::{Name, Record, RecordType};
        let domain = Name::from_ascii("example.net.").unwrap();
        let answers = hosts.iter().map(|host| {
            let exchange = Name::from_ascii(host).unwrap();
            Record::from_rdata(domain.clone(), 300, RData::MX(MX::new(10, exchange)))
        });
        Ok(Lookup::new_with_max_ttl(
            Query::query(domain.clone(), RecordType::MX),
            answers,
        ))
    }

    #[test]
    fn a_null_mx_takes_no_mail_but_a_host_beside_it_does() {
        assert_eq!(mail_hosts(mx(&["mail.example.net."])), Found::Yes);
        assert_eq!(mail_hosts(mx(&["."])), Found::No);
        assert_eq!(mail_hosts(mx(&[".", "mail.example.net."])), Found::Yes);
        assert_eq!(mail_hosts(mx(&[])), Found::None);
    }
}
