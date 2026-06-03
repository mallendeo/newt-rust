//! Client-side hole punching to exit nodes. Mirrors the site path but seals an
//! `olmId` payload. The exit nodes (with their relay ports and public keys) come
//! from the get-token response; the same get-token JWT is the hole-punch token.

use std::net::SocketAddr;

/// One exit node to keep punched: the relay socket address and the node's
/// public key (the seal target).
#[derive(Debug, Clone)]
pub struct ExitNode {
    pub addr: SocketAddr,
    pub server_pub: String,
}

/// Builds the periodic hole-punch datagrams for all known exit nodes.
pub struct HolePunch {
    olm_id: String,
    token: String,
    olm_pub: String,
    nodes: Vec<ExitNode>,
}

impl HolePunch {
    pub fn new(olm_id: String, olm_pub: String, token: String) -> Self {
        HolePunch { olm_id, olm_pub, token, nodes: Vec::new() }
    }

    pub fn set_nodes(&mut self, nodes: Vec<ExitNode>) { self.nodes = nodes; }

    pub fn is_empty(&self) -> bool { self.nodes.is_empty() }

    /// Sealed datagrams to send this tick, one per exit node.
    pub fn datagrams(&self) -> Vec<(Vec<u8>, SocketAddr)> {
        self.nodes
            .iter()
            .filter_map(|n| {
                crate::holepunch::build("olmId", &self.olm_id, &self.token, &self.olm_pub, &n.server_pub)
                    .map(|pkt| (pkt, n.addr))
            })
            .collect()
    }
}
