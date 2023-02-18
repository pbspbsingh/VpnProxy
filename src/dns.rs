use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use reqwest::{header, Client, Response};
use serde::Deserialize;
use tokio::time::Instant;

const CLOUDFLARE_API: &str = "https://cloudflare-dns.com/dns-query";
const DNS_JSON_TYPE: &str = "application/dns-json";
const DNS_MIME_TYPE: &str = "application/dns-message";

pub struct Dns {
    client: Client,
    cache: DashMap<String, (Vec<IpAddr>, Instant)>,
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("Http error: {0:?}")]
    HttpError(#[from] reqwest::Error),
    #[error("Bad DNS Request: {0} for {1}")]
    RequestError(u16, String),
    #[error("Failed to resolve the hostname: {0}")]
    ResolutionFailure(String),
}

impl From<DnsError> for std::io::Error {
    fn from(value: DnsError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, value.to_string())
    }
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
#[serde(rename_all(deserialize = "PascalCase"))]
struct DnsResponse {
    status: u32,
    question: Vec<Question>,
    answer: Option<Vec<Answer>>,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
struct Question {
    name: String,
    #[serde(rename(deserialize = "type"))]
    req_type: u32,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
struct Answer {
    name: String,
    #[serde(rename(deserialize = "type"))]
    res_type: u32,
    #[serde(rename(deserialize = "TTL"))]
    ttl: u32,
    data: String,
}

impl Dns {
    pub fn new() -> Self {
        let client = Client::builder().gzip(true).build().unwrap();
        let cache = DashMap::new();
        Dns { client, cache }
    }

    pub async fn resolve(&self, hostname: String) -> Result<Vec<IpAddr>, DnsError> {
        if let Some(entry) = self.cache.get(&hostname) {
            let (addrs, expiry) = entry.value();
            if Instant::now() > *expiry {
                log::debug!("Cache has expired for {hostname}");
                drop(entry);
                self.cache.remove(&hostname);
            } else {
                log::debug!("Cache hit: {hostname} => {addrs:?}");
                return Ok(addrs.clone());
            }
        }

        let (addrs, ttl) = self.inner_resolve(hostname.clone()).await?;
        if !addrs.is_empty() {
            let expiry = Instant::now() + Duration::from_secs(ttl as u64);
            log::debug!("Caching {hostname} for {ttl}s");
            self.cache.insert(hostname, (addrs.clone(), expiry));
        }
        Ok(addrs)
    }

    async fn inner_resolve(&self, hostname: String) -> Result<(Vec<IpAddr>, u32), DnsError> {
        let response = self.call_api(&hostname, true).await?;
        if !response.status().is_success() {
            return Err(DnsError::RequestError(
                response.status().as_u16(),
                hostname.clone(),
            ));
        }
        let dns_res = response.json::<DnsResponse>().await?;
        if let Some((v4_addrs, ttl)) = self.parse_answer(dns_res, true) {
            if !v4_addrs.is_empty() {
                return Ok((v4_addrs, ttl));
            }
        }

        let response = self.call_api(&hostname, false).await?;
        if !response.status().is_success() {
            return Err(DnsError::RequestError(
                response.status().as_u16(),
                hostname.clone(),
            ));
        }
        let dns_res = response.json::<DnsResponse>().await?;
        if let Some((v6_addrs, ttl)) = self.parse_answer(dns_res, false) {
            if !v6_addrs.is_empty() {
                return Ok((v6_addrs, ttl));
            }
        }

        Err(DnsError::ResolutionFailure(hostname))
    }

    async fn call_api(&self, hostname: &str, ipv4: bool) -> Result<Response, reqwest::Error> {
        let req_type = if ipv4 { "A" } else { "AAAA" };
        self.client
            .get(CLOUDFLARE_API)
            .header(header::ACCEPT, DNS_JSON_TYPE)
            .header(header::CONTENT_TYPE, DNS_MIME_TYPE)
            .query(&[("type", req_type), ("name", hostname)])
            .send()
            .await
    }

    fn parse_answer(&self, dns: DnsResponse, ipv4: bool) -> Option<(Vec<IpAddr>, u32)> {
        let que = dns.question.first()?;
        let answers = dns.answer?;
        let addrs = answers
            .iter()
            .filter(|ans| que.req_type == ans.res_type)
            .filter_map(|ans| {
                if ipv4 {
                    Ipv4Addr::from_str(&ans.data).ok().map(IpAddr::from)
                } else {
                    Ipv6Addr::from_str(&ans.data).ok().map(IpAddr::from)
                }
            })
            .collect();
        let ttl = answers
            .into_iter()
            .filter(|ans| que.req_type == ans.res_type)
            .map(|ans| ans.ttl)
            .min()
            .unwrap_or(60); // Default TTL 1 minute
        Some((addrs, ttl))
    }
}

#[cfg(test)]
mod test {
    use std::error::Error;

    #[tokio::test]
    async fn test_dns() -> Result<(), Box<dyn Error>> {
        let dns = super::Dns::new();
        dbg!(dns.resolve("www.amazon.com".into()).await?);
        dbg!(dns.resolve("amazon.com".into()).await?);
        dbg!(dns.resolve("fb.com".into()).await?);
        dbg!(&dns.cache);
        Ok(())
    }
}
