use base64::{engine::general_purpose::STANDARD, Engine as _};
use boringtun::x25519::{PublicKey, StaticSecret};

pub struct Keys {
    pub secret: StaticSecret,
    pub public_b64: String,
}

pub fn generate_keys() -> Keys {
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    Keys { public_b64: STANDARD.encode(public.as_bytes()), secret }
}

/// Decode a base64 WireGuard public key into the dalek PublicKey.
pub fn public_from_b64(s: &str) -> Result<PublicKey, String> {
    let raw = STANDARD.decode(s.trim()).map_err(|e| format!("bad pubkey b64: {e}"))?;
    let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| "pubkey not 32 bytes".to_string())?;
    Ok(PublicKey::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_roundtrip() {
        let k = generate_keys();
        let pk = public_from_b64(&k.public_b64).unwrap();
        assert_eq!(pk.as_bytes().len(), 32);
    }
}
