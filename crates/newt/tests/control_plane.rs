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

// Drives the hand-rolled WebSocket client against a tungstenite server to verify
// the upgrade handshake, client-side masking, frame parsing, and ping/pong.
#[tokio::test]
async fn ws_client_handshake_send_recv_and_pong() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();

        // Receive the client's text frame and confirm it round-trips as a WsMessage.
        let got = ws.next().await.unwrap().unwrap();
        let Message::Text(t) = got else { panic!("expected text frame") };
        let m: WsMessage = serde_json::from_str(&t).unwrap();
        assert_eq!(m.typ, "hello");

        // Reply, then ping and require the client's pong.
        let reply = WsMessage { typ: "world".into(), data: serde_json::json!({}), config_version: None };
        ws.send(Message::text(serde_json::to_string(&reply).unwrap())).await.unwrap();
        ws.send(Message::Ping(vec![1, 2, 3].into())).await.unwrap();
        let pong = ws.next().await.unwrap().unwrap();
        assert!(matches!(pong, Message::Pong(p) if p == vec![1u8, 2, 3]), "expected pong");
    });

    let tls = newt_lib::transport::tls::client_config(true);
    let mut sock = newt_lib::transport::ws::connect(&format!("http://{addr}"), "x", "newt", tls)
        .await
        .unwrap();
    let hello = WsMessage { typ: "hello".into(), data: serde_json::json!({}), config_version: None };
    newt_lib::transport::ws::send(&mut sock, &hello).await.unwrap();
    let reply = newt_lib::transport::ws::recv(&mut sock).await.unwrap().unwrap();
    assert_eq!(reply.typ, "world");
    // A second recv lets the client observe and answer the server's ping.
    let _ = newt_lib::transport::ws::recv(&mut sock).await;
    server.await.unwrap();
}
