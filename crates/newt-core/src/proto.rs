use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Control-channel envelope. Mirrors upstream newt's WSMessage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    #[serde(rename = "type")]
    pub typ: String,
    pub data: serde_json::Value,
    #[serde(rename = "configVersion", skip_serializing_if = "Option::is_none")]
    pub config_version: Option<i64>,
}

/// Topic constants used on the control channel.
pub mod topic {
    pub const PING_REQUEST: &str = "newt/ping/request";
    pub const PING_EXIT_NODES: &str = "newt/ping/exitNodes";
    pub const WG_REGISTER: &str = "newt/wg/register";
    pub const WG_CONNECT: &str = "newt/wg/connect";
    pub const WG_RECONNECT: &str = "newt/wg/reconnect";
    pub const WG_TERMINATE: &str = "newt/wg/terminate";
    pub const TCP_ADD: &str = "newt/tcp/add";
    pub const TCP_REMOVE: &str = "newt/tcp/remove";
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExitNode {
    #[serde(rename = "exitNodeId")]
    pub id: i64,
    #[serde(rename = "exitNodeName", default)]
    pub name: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub weight: f64,
    #[serde(rename = "wasPreviouslyConnected", default)]
    pub was_previously_connected: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExitNodeData {
    #[serde(rename = "exitNodes", default)]
    pub exit_nodes: Vec<ExitNode>,
    #[serde(rename = "chainId", default)]
    pub chain_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PingResult {
    #[serde(rename = "exitNodeId")]
    pub exit_node_id: i64,
    #[serde(rename = "latencyMs")]
    pub latency_ms: f64,
    pub weight: f64,
    pub error: String,
    pub name: String,
    pub endpoint: String,
    #[serde(rename = "wasPreviouslyConnected")]
    pub was_previously_connected: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TargetsByType {
    #[serde(default)]
    pub tcp: Vec<String>,
    #[serde(default)]
    pub udp: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WgData {
    #[serde(rename = "endpoint")]
    pub endpoint: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "serverIP")]
    pub server_ip: String,
    #[serde(rename = "tunnelIP")]
    pub tunnel_ip: String,
    #[serde(rename = "relayPort", default)]
    pub relay_port: u16,
    #[serde(default)]
    pub targets: TargetsByType,
    #[serde(rename = "chainId", default)]
    pub chain_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wg_connect_payload() {
        let raw = r#"{
            "endpoint":"1.2.3.4:51820","publicKey":"abc=","serverIP":"10.0.0.1",
            "tunnelIP":"10.0.0.2","relayPort":21820,
            "targets":{"tcp":["3001:127.0.0.1:80"],"udp":[]},"chainId":"x"
        }"#;
        let wg: WgData = serde_json::from_str(raw).unwrap();
        assert_eq!(wg.tunnel_ip, "10.0.0.2");
        assert_eq!(wg.relay_port, 21820);
        assert_eq!(wg.targets.tcp, alloc::vec!["3001:127.0.0.1:80"]);
    }

    #[test]
    fn roundtrips_envelope() {
        let m = WsMessage {
            typ: topic::PING_REQUEST.into(),
            data: serde_json::json!({"noCloud": false, "chainId": "c1"}),
            config_version: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"type\":\"newt/ping/request\""));
        assert!(!s.contains("configVersion"));
    }
}
