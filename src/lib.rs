use std::io;
use std::net::IpAddr;

pub mod dns;
pub mod socks;
mod util;

use crate::dns::Dns;
use async_trait::async_trait;

#[async_trait]
pub trait Resolver: Send {
    async fn resolve(&self, host: String) -> io::Result<Vec<IpAddr>>;
}

#[async_trait]
impl Resolver for Dns {
    async fn resolve(&self, host: String) -> io::Result<Vec<IpAddr>> {
        Ok(self.resolve(host).await?)
    }
}
