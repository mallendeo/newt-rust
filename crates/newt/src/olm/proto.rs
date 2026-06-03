//! Client (olm) control-channel message shapes. The envelope is the shared
//! `newt_core::proto::WsMessage`; these are the olm-specific `data` payloads.

use serde::Deserialize;

/// Topics on the olm control channel.
pub mod topic {
    // outbound (client -> server)
    pub const REGISTER: &str = "olm/wg/register";
    pub const DISCONNECTING: &str = "olm/disconnecting";
    // inbound (server -> client)
    pub const CONNECT: &str = "olm/wg/connect";
    pub const ERROR: &str = "olm/error";
    pub const TERMINATE: &str = "olm/terminate";
    pub const PEER_ADD: &str = "olm/wg/peer/add";
    pub const PEER_REMOVE: &str = "olm/wg/peer/remove";
    pub const PEER_UPDATE: &str = "olm/wg/peer/update";
    pub const PEER_RELAY: &str = "olm/wg/peer/relay";
    pub const PEER_UNRELAY: &str = "olm/wg/peer/unrelay";
    pub const PEER_DATA_ADD: &str = "olm/wg/peer/data/add";
    pub const PEER_DATA_REMOVE: &str = "olm/wg/peer/data/remove";
    pub const PEER_DATA_UPDATE: &str = "olm/wg/peer/data/update";
    pub const SYNC: &str = "olm/sync";
}

/// A site the client can reach. `endpoint`/`relay_endpoint` is the WireGuard
/// endpoint to send this peer's encrypted traffic to (relay = through the exit
/// node). `remote_subnets` + `allowed_ips` are the destinations routed to it.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SiteConfig {
    #[serde(rename = "siteId")]
    pub site_id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(rename = "relayEndpoint", default)]
    pub relay_endpoint: String,
    #[serde(rename = "publicKey", default)]
    pub public_key: String,
    #[serde(rename = "serverIP", default)]
    pub server_ip: String,
    #[serde(rename = "serverPort", default)]
    pub server_port: u16,
    #[serde(rename = "remoteSubnets", default)]
    pub remote_subnets: Vec<String>,
    #[serde(rename = "allowedIps", default)]
    pub allowed_ips: Vec<String>,
}

impl SiteConfig {
    /// Effective WireGuard endpoint: the relay endpoint when present (relay
    /// mode), otherwise the direct endpoint.
    pub fn wg_endpoint(&self) -> &str {
        if !self.relay_endpoint.is_empty() { &self.relay_endpoint } else { &self.endpoint }
    }

    /// All destination CIDRs routed to this site.
    pub fn routed_cidrs(&self) -> impl Iterator<Item = &String> {
        self.remote_subnets.iter().chain(self.allowed_ips.iter())
    }
}

/// `olm/wg/connect` payload: the full initial peer set plus our addressing.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WgData {
    #[serde(default)]
    pub sites: Vec<SiteConfig>,
    #[serde(rename = "tunnelIP", default)]
    pub tunnel_ip: String,
    #[serde(rename = "utilitySubnet", default)]
    pub utility_subnet: String,
}

/// `olm/wg/peer/remove` payload.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerRemove {
    #[serde(rename = "siteId")]
    pub site_id: i64,
}

/// `olm/wg/peer/relay` payload: switch a peer onto a relay endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerRelay {
    #[serde(rename = "siteId")]
    pub site_id: i64,
    #[serde(rename = "relayEndpoint")]
    pub relay_endpoint: String,
}

/// `olm/wg/peer/unrelay` payload: switch a peer onto a direct endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerUnrelay {
    #[serde(rename = "siteId")]
    pub site_id: i64,
    pub endpoint: String,
}

/// `olm/wg/peer/data/{add,remove}` payload: change routed subnets for a peer.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerData {
    #[serde(rename = "siteId")]
    pub site_id: i64,
    #[serde(rename = "remoteSubnets", default)]
    pub remote_subnets: Vec<String>,
}

/// `olm/wg/peer/data/update` payload.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerDataUpdate {
    #[serde(rename = "siteId")]
    pub site_id: i64,
    #[serde(rename = "oldRemoteSubnets", default)]
    pub old_remote_subnets: Vec<String>,
    #[serde(rename = "newRemoteSubnets", default)]
    pub new_remote_subnets: Vec<String>,
}

/// `olm/error` / `olm/terminate` payload.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ErrorData {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub message: String,
}

/// `olm/sync` payload: authoritative current peer set.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SyncData {
    #[serde(default)]
    pub sites: Vec<SiteConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_with_sites() {
        let raw = r#"{
            "tunnelIP":"100.89.0.5","utilitySubnet":"100.90.0.0/24",
            "sites":[{
                "siteId":7,"name":"hq","publicKey":"abc=",
                "relayEndpoint":"1.2.3.4:21820","endpoint":"5.6.7.8:51820",
                "remoteSubnets":["10.0.0.0/24"],"allowedIps":["100.89.0.7/32"]
            }]
        }"#;
        let wg: WgData = serde_json::from_str(raw).unwrap();
        assert_eq!(wg.tunnel_ip, "100.89.0.5");
        assert_eq!(wg.sites.len(), 1);
        let s = &wg.sites[0];
        assert_eq!(s.site_id, 7);
        assert_eq!(s.wg_endpoint(), "1.2.3.4:21820");
        let cidrs: Vec<&String> = s.routed_cidrs().collect();
        assert_eq!(cidrs.len(), 2);
    }

    #[test]
    fn wg_endpoint_falls_back_to_direct() {
        let s = SiteConfig { endpoint: "9.9.9.9:51820".into(), ..Default::default() };
        assert_eq!(s.wg_endpoint(), "9.9.9.9:51820");
    }
}
