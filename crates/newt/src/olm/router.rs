//! Multi-peer WireGuard router shared by both olm backends. Holds one boringtun
//! session per site, routes outbound IP packets to the peer that owns the
//! destination (longest-prefix match over allowed CIDRs), and demultiplexes
//! inbound datagrams back to the owning peer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use boringtun::x25519::StaticSecret;
use crate::wg::{self, Inbound, Pump};

/// A routed destination range.
#[derive(Debug, Clone, Copy)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse "10.0.0.0/24" or a bare address (treated as a host route).
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let net: IpAddr = addr.parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max { return None; }
        Some(Cidr { net, prefix })
    }

    pub fn prefix(&self) -> u8 { self.prefix }

    /// Network address and prefix length (for programming OS routes).
    pub fn parts(&self) -> (IpAddr, u8) { (self.net, self.prefix) }

    /// Does this range contain `ip`? Compares the first `prefix` bits.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => bits_match(&n.octets(), &a.octets(), self.prefix),
            (IpAddr::V6(n), IpAddr::V6(a)) => bits_match(&n.octets(), &a.octets(), self.prefix),
            _ => false,
        }
    }
}

/// Compare the first `prefix` bits of two byte arrays.
fn bits_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] { return false; }
    let rem = prefix % 8;
    if rem == 0 { return true; }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Result of feeding an inbound datagram to the router.
pub enum Out {
    /// A decrypted IP packet to deliver to the host.
    ToHost(Vec<u8>),
    /// Bytes to write back to a peer endpoint (handshake/cookie).
    ToNet(Vec<u8>, SocketAddr),
}

struct Peer {
    site_id: i64,
    pump: Pump,
    endpoint: SocketAddr,
    cidrs: Vec<Cidr>,
    index: u32,
}

/// The router. Construct with our private key + MTU, then add peers.
pub struct Router {
    secret: StaticSecret,
    mtu: usize,
    peers: Vec<Peer>,
    next_index: u32,
}

impl Router {
    pub fn new(secret: StaticSecret, mtu: usize) -> Self {
        Router { secret, mtu, peers: Vec::new(), next_index: 1 }
    }

    pub fn peer_count(&self) -> usize { self.peers.len() }

    /// Add or replace the peer for `site_id`. Returns the handshake initiation
    /// to send (so the session comes up without waiting for outbound data),
    /// paired with the peer endpoint.
    pub fn upsert_peer(
        &mut self,
        site_id: i64,
        peer_pub_b64: &str,
        endpoint: SocketAddr,
        cidrs: Vec<Cidr>,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        let peer_pub = wg::public_from_b64(peer_pub_b64).ok()?;
        self.remove_peer(site_id);
        let index = self.next_index;
        self.next_index = self.next_index.wrapping_add(1).max(1);
        let mut pump = Pump::with_index(self.secret.clone(), peer_pub, self.mtu, index);
        let init = pump.initiate_handshake().map(|b| (b, endpoint));
        self.peers.push(Peer { site_id, pump, endpoint, cidrs, index });
        init
    }

    pub fn remove_peer(&mut self, site_id: i64) {
        self.peers.retain(|p| p.site_id != site_id);
    }

    /// Replace the endpoint for a peer (relay/unrelay), keeping its session.
    pub fn set_endpoint(&mut self, site_id: i64, endpoint: SocketAddr) {
        if let Some(p) = self.peers.iter_mut().find(|p| p.site_id == site_id) {
            p.endpoint = endpoint;
        }
    }

    pub fn set_cidrs(&mut self, site_id: i64, cidrs: Vec<Cidr>) {
        if let Some(p) = self.peers.iter_mut().find(|p| p.site_id == site_id) {
            p.cidrs = cidrs;
        }
    }

    pub fn add_cidrs(&mut self, site_id: i64, mut cidrs: Vec<Cidr>) {
        if let Some(p) = self.peers.iter_mut().find(|p| p.site_id == site_id) {
            p.cidrs.append(&mut cidrs);
        }
    }

    pub fn remove_cidrs(&mut self, site_id: i64, drop: &[Cidr]) {
        if let Some(p) = self.peers.iter_mut().find(|p| p.site_id == site_id) {
            p.cidrs.retain(|c| !drop.iter().any(|d| same_cidr(c, d)));
        }
    }

    /// All CIDRs currently routed (for programming OS routes).
    pub fn all_cidrs(&self) -> Vec<(i64, Cidr)> {
        self.peers.iter().flat_map(|p| p.cidrs.iter().map(move |c| (p.site_id, *c))).collect()
    }

    /// Index of the peer that owns `dst` by longest-prefix match.
    fn best_peer(&self, dst: IpAddr) -> Option<usize> {
        let mut best: Option<(usize, u8)> = None;
        for (i, p) in self.peers.iter().enumerate() {
            for c in &p.cidrs {
                if c.contains(dst) && best.map_or(true, |(_, bp)| c.prefix() > bp) {
                    best = Some((i, c.prefix()));
                }
            }
        }
        best.map(|(i, _)| i)
    }

    /// The peer endpoint a destination routes to, without encrypting (routing
    /// decision only).
    pub fn route_target(&self, dst: IpAddr) -> Option<SocketAddr> {
        self.best_peer(dst).map(|i| self.peers[i].endpoint)
    }

    /// Route an outbound plaintext IP packet to its peer and encrypt it. Returns
    /// None when no peer owns the destination, or when the session is not yet
    /// established (boringtun queues the packet until the handshake completes).
    pub fn route_outbound(&mut self, ip_pkt: &[u8]) -> Option<(Vec<u8>, SocketAddr)> {
        let dst = dest_ip(ip_pkt)?;
        let i = self.best_peer(dst)?;
        let endpoint = self.peers[i].endpoint;
        let dg = self.peers[i].pump.encapsulate(ip_pkt)?;
        Some((dg, endpoint))
    }

    /// Feed an inbound datagram; returns decrypted IP packets to deliver to the
    /// host and any bytes that must be written back to the peer
    /// (handshake/cookie), each already paired with that peer's endpoint.
    pub fn handle_inbound(&mut self, datagram: &[u8]) -> Vec<Out> {
        let Some(peer_idx) = wg::peer_index_of(datagram) else { return Vec::new(); };
        let Some(p) = self.peers.iter_mut().find(|p| p.index == peer_idx) else { return Vec::new(); };
        let endpoint = p.endpoint;
        let mut out = Vec::new();
        let push = |inb: Inbound, out: &mut Vec<Out>| match inb {
            Inbound::Packet(pkt) => out.push(Out::ToHost(pkt)),
            Inbound::Network(b) => out.push(Out::ToNet(b, endpoint)),
            Inbound::Nothing => {}
        };
        push(p.pump.decapsulate(datagram), &mut out);
        loop {
            match p.pump.drain() {
                Inbound::Nothing => break,
                more => push(more, &mut out),
            }
        }
        out
    }

    /// Drive every peer's WireGuard timers; returns datagrams to send.
    pub fn tick(&mut self) -> Vec<(Vec<u8>, SocketAddr)> {
        let mut out = Vec::new();
        for p in &mut self.peers {
            if let Some(b) = p.pump.update_timers() {
                out.push((b, p.endpoint));
            }
        }
        out
    }
}

fn same_cidr(a: &Cidr, b: &Cidr) -> bool {
    a.prefix == b.prefix && a.net == b.net
}

/// Destination IP of a bare IPv4/IPv6 packet.
fn dest_ip(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))),
        6 if pkt.len() >= 40 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&pkt[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::x25519::PublicKey;

    #[test]
    fn cidr_contains_v4() {
        let c = Cidr::parse("10.0.0.0/24").unwrap();
        assert!(c.contains("10.0.0.5".parse().unwrap()));
        assert!(!c.contains("10.0.1.5".parse().unwrap()));
        let host = Cidr::parse("10.0.0.7").unwrap();
        assert_eq!(host.prefix(), 32);
        assert!(host.contains("10.0.0.7".parse().unwrap()));
        assert!(!host.contains("10.0.0.8".parse().unwrap()));
    }

    #[test]
    fn cidr_odd_prefix() {
        let c = Cidr::parse("192.168.0.0/20").unwrap();
        assert!(c.contains("192.168.5.1".parse().unwrap()));
        assert!(!c.contains("192.168.16.1".parse().unwrap()));
    }

    fn router() -> Router {
        Router::new(StaticSecret::random_from_rng(rand_core::OsRng), 1280)
    }

    fn a_pubkey() -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let s = StaticSecret::random_from_rng(rand_core::OsRng);
        STANDARD.encode(PublicKey::from(&s).as_bytes())
    }

    #[test]
    fn upsert_emits_handshake_and_routes_by_prefix() {
        let mut r = router();
        let ep1: SocketAddr = "1.1.1.1:51820".parse().unwrap();
        let ep2: SocketAddr = "2.2.2.2:51820".parse().unwrap();
        let init = r.upsert_peer(1, &a_pubkey(), ep1, vec![Cidr::parse("10.0.0.0/16").unwrap()]);
        assert!(init.is_some(), "handshake initiation expected");
        r.upsert_peer(2, &a_pubkey(), ep2, vec![Cidr::parse("10.0.5.0/24").unwrap()]);
        assert_eq!(r.peer_count(), 2);

        // 10.0.5.9 matches both /16 (peer1) and /24 (peer2): longest prefix wins -> peer2/ep2.
        assert_eq!(r.route_target("10.0.5.9".parse().unwrap()), Some(ep2));
        // 10.0.9.9 matches only peer1.
        assert_eq!(r.route_target("10.0.9.9".parse().unwrap()), Some(ep1));
        // Unroutable destination.
        assert_eq!(r.route_target("8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn upsert_replaces_same_site() {
        let mut r = router();
        let ep: SocketAddr = "1.1.1.1:1".parse().unwrap();
        r.upsert_peer(1, &a_pubkey(), ep, vec![Cidr::parse("10.0.0.0/24").unwrap()]);
        r.upsert_peer(1, &a_pubkey(), ep, vec![Cidr::parse("10.0.0.0/24").unwrap()]);
        assert_eq!(r.peer_count(), 1);
        r.remove_peer(1);
        assert_eq!(r.peer_count(), 0);
    }

    /// Minimal IPv4 header with the given destination (src 0.0.0.0, proto 0).
    fn ipv4_to(dst: &str) -> Vec<u8> {
        let d: Ipv4Addr = dst.parse().unwrap();
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&d.octets());
        p
    }
}
