use alloc::string::String;
use alloc::vec::Vec;
use crate::proto::{ExitNodeData, WgData, WsMessage};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Disconnected,
    RequestingExitNodes,
    Registering,
    Connected,
    Stopped,
}

#[derive(Debug)]
pub enum Event {
    WsConnected,
    ExitNodes(ExitNodeData),
    WgConnect(WgData),
    Reconnect,
    Terminate,
    /// Periodic tick; carries elapsed milliseconds since the last tick.
    Tick(u64),
}

#[derive(Debug)]
pub enum Action {
    /// Send this control message now.
    Send(WsMessage),
    /// Bring up the WireGuard tunnel + proxy with this config.
    BringUp(WgData),
    /// Tear down the tunnel + proxy.
    Teardown,
    /// Stop the client entirely.
    Stop,
}

pub struct Sm {
    pub state: State,
    public_key_b64: String,
    newt_version: String,
    no_cloud: bool,
    pending_chain_id: String,
    resend_due_ms: u64,
}

const PING_RESEND_MS: u64 = 3000;
const REGISTER_RESEND_MS: u64 = 2000;

impl Sm {
    pub fn new(public_key_b64: String, newt_version: String, no_cloud: bool) -> Self {
        Sm {
            state: State::Disconnected,
            public_key_b64,
            newt_version,
            no_cloud,
            pending_chain_id: String::new(),
            resend_due_ms: 0,
        }
    }

    pub fn step(&mut self, ev: Event) -> Vec<Action> { step_impl(self, ev) }
}

use crate::proto::{topic, PingResult};
use serde_json::json;

fn ping_request_msg(sm: &Sm) -> WsMessage {
    WsMessage {
        typ: topic::PING_REQUEST.into(),
        data: json!({ "noCloud": sm.no_cloud, "chainId": sm.pending_chain_id }),
        config_version: None,
    }
}

fn register_msg(sm: &Sm, results: &[PingResult]) -> WsMessage {
    WsMessage {
        typ: topic::WG_REGISTER.into(),
        data: json!({
            "publicKey": sm.public_key_b64,
            "pingResults": results,
            "newtVersion": sm.newt_version,
            "chainId": sm.pending_chain_id,
        }),
        config_version: None,
    }
}

fn step_impl(sm: &mut Sm, ev: Event) -> Vec<Action> {
    let mut out = Vec::new();
    match ev {
        Event::WsConnected => {
            sm.state = State::RequestingExitNodes;
            sm.resend_due_ms = PING_RESEND_MS;
            out.push(Action::Send(ping_request_msg(sm)));
        }
        Event::ExitNodes(data) => {
            if sm.state != State::RequestingExitNodes { return out; }
            let Some(node) = data.exit_nodes.into_iter().next() else { return out; };
            let results = [PingResult {
                exit_node_id: node.id,
                latency_ms: 0.0,
                weight: node.weight,
                error: String::new(),
                name: node.name,
                endpoint: node.endpoint,
                was_previously_connected: node.was_previously_connected,
            }];
            sm.state = State::Registering;
            sm.resend_due_ms = REGISTER_RESEND_MS;
            out.push(Action::Send(register_msg(sm, &results)));
        }
        Event::WgConnect(wg) => {
            if sm.state == State::Connected {
                out.push(Action::Teardown);
            }
            sm.state = State::Connected;
            sm.resend_due_ms = 0;
            out.push(Action::BringUp(wg));
        }
        Event::Reconnect => {
            if sm.state == State::Connected { out.push(Action::Teardown); }
            sm.state = State::RequestingExitNodes;
            sm.resend_due_ms = PING_RESEND_MS;
            out.push(Action::Send(ping_request_msg(sm)));
        }
        Event::Terminate => {
            out.push(Action::Teardown);
            out.push(Action::Stop);
            sm.state = State::Stopped;
        }
        Event::Tick(elapsed) => {
            if sm.resend_due_ms == 0 { return out; }
            if elapsed >= sm.resend_due_ms {
                match sm.state {
                    State::RequestingExitNodes => {
                        sm.resend_due_ms = PING_RESEND_MS;
                        out.push(Action::Send(ping_request_msg(sm)));
                    }
                    State::Registering => {
                        sm.resend_due_ms = REGISTER_RESEND_MS;
                        out.push(Action::Send(register_msg(sm, &[])));
                    }
                    _ => {}
                }
            } else {
                sm.resend_due_ms -= elapsed;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sm() -> Sm { Sm::new("PUBKEY".into(), "rust-0.1.0".into(), false) }

    #[test]
    fn requests_exit_nodes_on_connect() {
        let mut sm = sm();
        let acts = sm.step(Event::WsConnected);
        assert_eq!(sm.state, State::RequestingExitNodes);
        match &acts[0] {
            Action::Send(m) => assert_eq!(m.typ, crate::proto::topic::PING_REQUEST),
            _ => panic!("expected Send ping/request"),
        }
    }

    #[test]
    fn registers_with_first_exit_node() {
        let mut sm = sm();
        sm.step(Event::WsConnected);
        let data: ExitNodeData = serde_json::from_str(
            r#"{"exitNodes":[{"exitNodeId":7,"endpoint":"e:1","weight":1.0}],"chainId":""}"#,
        ).unwrap();
        let acts = sm.step(Event::ExitNodes(data));
        assert_eq!(sm.state, State::Registering);
        match &acts[0] {
            Action::Send(m) => {
                assert_eq!(m.typ, crate::proto::topic::WG_REGISTER);
                assert!(m.data["pingResults"][0]["exitNodeId"] == 7);
            }
            _ => panic!("expected Send wg/register"),
        }
    }

    #[test]
    fn brings_up_on_wg_connect() {
        let mut sm = sm();
        sm.step(Event::WsConnected);
        let data: ExitNodeData = serde_json::from_str(
            r#"{"exitNodes":[{"exitNodeId":7,"endpoint":"e:1"}],"chainId":""}"#).unwrap();
        sm.step(Event::ExitNodes(data));
        let wg: WgData = serde_json::from_str(
            r#"{"endpoint":"1.2.3.4:51820","publicKey":"k","serverIP":"10.0.0.1","tunnelIP":"10.0.0.2"}"#).unwrap();
        let acts = sm.step(Event::WgConnect(wg));
        assert_eq!(sm.state, State::Connected);
        assert!(acts.iter().any(|a| matches!(a, Action::BringUp(_))));
    }

    #[test]
    fn reconnect_tears_down_and_rerequests() {
        let mut sm = sm();
        sm.state = State::Connected;
        let acts = sm.step(Event::Reconnect);
        assert!(matches!(acts[0], Action::Teardown));
        assert_eq!(sm.state, State::RequestingExitNodes);
    }

    #[test]
    fn tick_resends_pending_request() {
        let mut sm = sm();
        sm.step(Event::WsConnected); // schedules a resend at +3000ms
        let acts = sm.step(Event::Tick(PING_RESEND_MS));
        assert!(matches!(acts.first(), Some(Action::Send(_))));
    }
}
