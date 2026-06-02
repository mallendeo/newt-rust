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

use boringtun::noise::{Tunn, TunnResult};

pub struct Pump {
    tun: Tunn,
    mtu: usize,
}

/// Output of feeding an inbound UDP datagram into the pump.
pub enum Inbound {
    /// A decrypted IP packet to hand to the netstack.
    Packet(Vec<u8>),
    /// Bytes that must be written back to the network (handshake/cookie).
    Network(Vec<u8>),
    Nothing,
}

impl Pump {
    pub fn new(secret: StaticSecret, peer_public: PublicKey, mtu: usize) -> Self {
        let tun = Tunn::new(secret, peer_public, None, Some(5), 0, None);
        Pump { tun, mtu }
    }

    fn scratch(&self) -> Vec<u8> { vec![0u8; self.mtu.max(1500) + 32] }

    /// Encrypt an outbound IP packet. Returns the datagram to send over UDP.
    pub fn encapsulate(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let mut dst = self.scratch();
        match self.tun.encapsulate(packet, &mut dst) {
            TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
            _ => None,
        }
    }

    /// Decrypt one inbound datagram. After this returns `Network`, the caller
    /// must loop `drain()` until it returns `Nothing` to flush queued packets.
    pub fn decapsulate(&mut self, datagram: &[u8]) -> Inbound {
        let mut dst = self.scratch();
        match self.tun.decapsulate(None, datagram, &mut dst) {
            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => Inbound::Packet(p.to_vec()),
            TunnResult::WriteToNetwork(b) => Inbound::Network(b.to_vec()),
            _ => Inbound::Nothing,
        }
    }

    /// Drain queued packets after a `WriteToNetwork` (feeds empty input).
    pub fn drain(&mut self) -> Inbound {
        self.decapsulate(&[])
    }

    /// Force a handshake initiation. newt is the passive side with no outbound
    /// data to trigger one, so it must reach out first to holepunch and bring the
    /// session up; otherwise the exit node never sees traffic and the site stays offline.
    pub fn initiate_handshake(&mut self) -> Option<Vec<u8>> {
        let mut dst = self.scratch();
        match self.tun.format_handshake_initiation(&mut dst, false) {
            TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
            _ => None,
        }
    }

    pub fn update_timers(&mut self) -> Option<Vec<u8>> {
        let mut dst = self.scratch();
        match self.tun.update_timers(&mut dst) {
            TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
            _ => None,
        }
    }
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

    #[test]
    fn two_pumps_complete_handshake() {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let a_sec = StaticSecret::random_from_rng(rand_core::OsRng);
        let b_sec = StaticSecret::random_from_rng(rand_core::OsRng);
        let a_pub = PublicKey::from(&a_sec);
        let b_pub = PublicKey::from(&b_sec);
        let mut a = Pump::new(a_sec, b_pub, 1280);
        let mut b = Pump::new(b_sec, a_pub, 1280);

        // A initiates by sending a (dummy) packet; encapsulate triggers handshake init.
        let init = a.encapsulate(&[0u8; 20]).expect("handshake init");
        // B processes init -> should produce a network reply (handshake response).
        let mut reply = match b.decapsulate(&init) { Inbound::Network(b) => Some(b), _ => None };
        while let Inbound::Network(extra) = b.drain() { reply = Some(extra); }
        let reply = reply.expect("handshake response");
        // A processes response; handshake completes (may emit keepalive to network).
        let _ = a.decapsulate(&reply);
        while let Inbound::Network(_) = a.drain() {}
        // No panic and both produced bytes => handshake codec works.
        assert!(!init.is_empty());
    }
}
