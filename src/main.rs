use std::env;
use std::error::Error;

use vpn_proxy::socks::Socks5;

const LOG: &str = "RUST_LOG";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if env::var(LOG).is_err() {
        println!("{LOG} env var is not set, defaulting to 'debug'");
        env::set_var(LOG, "debug");
    }
    pretty_env_logger::init();

    let socks5 = Socks5::default(1150).await?;
    Ok(socks5.serve().await?)
}
