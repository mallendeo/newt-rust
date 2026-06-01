use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use newt_core::proto::{topic, WsMessage};

#[tokio::test]
async fn handshake_reaches_wg_register() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let mut saw_ping = false;
        let mut saw_register = false;
        // 1. expect ping/request, reply with one exit node
        while let Some(Ok(msg)) = ws.next().await {
            if let Message::Text(t) = msg {
                let m: WsMessage = serde_json::from_str(&t).unwrap();
                if m.typ == topic::PING_REQUEST && !saw_ping {
                    saw_ping = true;
                    let reply = WsMessage {
                        typ: topic::PING_EXIT_NODES.into(),
                        data: serde_json::json!({"exitNodes":[{"exitNodeId":1,"endpoint":"127.0.0.1:1"}],"chainId":""}),
                        config_version: None,
                    };
                    ws.send(Message::text(serde_json::to_string(&reply).unwrap())).await.unwrap();
                } else if m.typ == topic::WG_REGISTER {
                    saw_register = true;
                    break;
                }
            }
        }
        assert!(saw_ping && saw_register, "server saw ping={saw_ping} register={saw_register}");
    });

    // Client side: drive the state machine over a plain ws:// (no TLS) connection.
    let url = format!("ws://{addr}/api/v1/ws?token=x&clientType=newt");
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();

    let mut sm = newt_core::sm::Sm::new("PUB".into(), "rust-test".into(), false);
    for act in sm.step(newt_core::sm::Event::WsConnected) { send_act(&mut ws, act).await; }
    while let Some(Ok(Message::Text(t))) = ws.next().await {
        let m: WsMessage = serde_json::from_str(&t).unwrap();
        let ev = match m.typ.as_str() {
            topic::PING_EXIT_NODES => Some(newt_core::sm::Event::ExitNodes(serde_json::from_value(m.data).unwrap())),
            _ => None,
        };
        if let Some(ev) = ev {
            for act in sm.step(ev) { send_act(&mut ws, act).await; }
            break;
        }
    }
    server.await.unwrap();
}

async fn send_act(ws: &mut (impl SinkExt<Message> + Unpin), act: newt_core::sm::Action) {
    if let newt_core::sm::Action::Send(m) = act {
        let _ = ws.send(Message::text(serde_json::to_string(&m).unwrap())).await;
    }
}
