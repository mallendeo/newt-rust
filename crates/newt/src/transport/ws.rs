use std::sync::Arc;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
use newt_core::proto::WsMessage;

pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Connect to wss://<endpoint>/api/v1/ws?token=..&clientType=newt.
pub async fn connect(
    endpoint: &str,
    token: &str,
    tls: Arc<rustls::ClientConfig>,
) -> std::io::Result<Ws> {
    let (scheme, _hp, _h, _p) = super::token::split_endpoint(endpoint)?;
    let ws_scheme = if scheme == "https" { "wss" } else { "ws" };
    let base = endpoint.split_once("://").map(|x| x.1).unwrap_or(endpoint).trim_end_matches('/');
    let url = format!("{ws_scheme}://{base}/api/v1/ws?token={token}&clientType=newt");

    let req = url.into_client_request().map_err(|e| std::io::Error::other(e.to_string()))?;
    let connector = Connector::Rustls(tls);
    let (stream, _resp) = connect_async_tls_with_config(req, None, false, Some(connector))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(stream)
}

pub async fn send(ws: &mut Ws, msg: &WsMessage) -> std::io::Result<()> {
    let text = serde_json::to_string(msg).map_err(std::io::Error::other)?;
    ws.send(Message::Text(text.into())).await.map_err(|e| std::io::Error::other(e.to_string()))
}

/// Receive the next control message, skipping ping/pong/binary frames.
pub async fn recv(ws: &mut Ws) -> std::io::Result<Option<WsMessage>> {
    while let Some(frame) = ws.next().await {
        match frame.map_err(|e| std::io::Error::other(e.to_string()))? {
            Message::Text(t) => {
                let m: WsMessage = serde_json::from_str(&t).map_err(std::io::Error::other)?;
                return Ok(Some(m));
            }
            Message::Close(_) => return Ok(None),
            _ => continue,
        }
    }
    Ok(None)
}
