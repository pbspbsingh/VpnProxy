use std::error::Error;

use vpn_proxy::dns::Dns;
use vpn_proxy::socks::Socks5;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    std::env::set_var("RUST_LOG", "debug");
    pretty_env_logger::init();

    let socks5 = Socks5::default(1150, Dns::new()).await?;
    Ok(socks5.serve().await?)
}
