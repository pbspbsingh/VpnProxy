use std::net::Ipv4Addr;

use log::debug;
use smoltcp::wire::Ipv4Cidr;
use wireguard_keys::{ParseError, Privkey, Pubkey};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn u8s_to_u16(a: u8, b: u8) -> u16 {
    ((a as u16) << 8) | (b as u16)
}

pub fn parse_cidr(input: &str) -> Ipv4Cidr {
    let (addr, mask) = if let Some(idx) = input.find('/') {
        (&input[..idx], &input[idx + 1..])
    } else {
        (input, "32")
    };
    debug!("Local address: {addr}, with mask: {mask}");
    let addr = addr
        .parse::<Ipv4Addr>()
        .unwrap_or_else(|e| panic!("Failed to parse the ipv4 address from {addr}: {e}"));
    let mask = mask
        .parse::<u8>()
        .unwrap_or_else(|e| panic!("Failed to parse masking bytes from {mask}: {e}"));
    Ipv4Cidr::new(addr.into(), mask)
}

pub fn parse_private_key(key: impl AsRef<str>) -> Result<StaticSecret, ParseError> {
    let priv_key = Privkey::parse(key.as_ref())?;
    let mut data = [0_u8; 32];
    data.copy_from_slice(&*priv_key);
    Ok(StaticSecret::from(data))
}

pub fn parse_public_key(key: impl AsRef<str>) -> Result<PublicKey, ParseError> {
    let priv_key = Pubkey::parse(key.as_ref())?;
    let mut data = [0_u8; 32];
    data.copy_from_slice(&*priv_key);
    Ok(PublicKey::from(data))
}

#[cfg(test)]
mod test {
    use wireguard_keys::Privkey;

    use crate::PUBLIC_KEY;

    #[test]
    fn parse_private_key() {
        let priv_key = Privkey::parse(PUBLIC_KEY).unwrap();

        println!("{}", priv_key.len());
    }
}
