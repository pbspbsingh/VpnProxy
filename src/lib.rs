pub mod dns;
pub mod socks;
mod util;
mod wg;

const PRIVATE_KEY: &str = "mHFKvtb0dBC5omikHaXMTU55W6kTuVdUY+tK/BAo038=";
const PUBLIC_KEY: &str = "VUp/Ro7hB3T5d5IvmSkamNM+zNP2Mb1M/zEZh4GHYFU=";

const LOCAL_ADDRESS: &str = "10.2.0.2/32";
const PEER_ADDRESS: &str = "172.83.40.66:51820";
