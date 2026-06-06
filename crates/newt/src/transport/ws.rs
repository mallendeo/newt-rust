use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand_core::{OsRng, RngCore};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use newt_core::proto::WsMessage;

/// Largest control-plane frame we accept; guards against a hostile length field.
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// A WebSocket connection over either a plain TCP or a rustls TLS stream.
pub struct Ws {
    inner: Inner,
}

enum Inner {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Inner {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Inner::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Inner::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Inner {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Inner::Plain(s) => Pin::new(s).poll_write(cx, b),
            Inner::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, b),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Inner::Plain(s) => Pin::new(s).poll_flush(cx),
            Inner::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Inner::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Inner::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Connect to ws(s)://<endpoint>/api/v1/ws?token=..&clientType=<client_type> and
/// complete the WebSocket upgrade. `client_type` is "newt" for a site session or
/// "olm" for a client session.
pub async fn connect(
    endpoint: &str,
    token: &str,
    client_type: &str,
    tls: Arc<rustls::ClientConfig>,
) -> std::io::Result<Ws> {
    let (scheme, hostport, host, port) = super::token::split_endpoint(endpoint)?;

    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    tcp.set_nodelay(true).ok();
    let mut inner = if scheme == "https" {
        let dns = ServerName::try_from(host.clone()).map_err(|_| std::io::Error::other("bad server name"))?;
        let tls = TlsConnector::from(tls).connect(dns, tcp).await?;
        Inner::Tls(Box::new(tls))
    } else {
        Inner::Plain(tcp)
    };

    let mut key = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    let key_b64 = STANDARD.encode(key);
    let req = format!(
        "GET /api/v1/ws?token={token}&clientType={client_type} HTTP/1.1\r\n\
         Host: {hostport}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key_b64}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    inner.write_all(req.as_bytes()).await?;
    inner.flush().await?;

    // Read the response headers up to the blank line. read_exact never over-reads,
    // so any WebSocket frames the server sends next stay buffered for recv().
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    loop {
        inner.read_exact(&mut b).await?;
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 8192 {
            return Err(std::io::Error::other("websocket upgrade headers too large"));
        }
    }
    let status = head.split(|&c| c == b'\r').next().unwrap_or(&[]);
    if !status.starts_with(b"HTTP/1.1 101") {
        return Err(std::io::Error::other(format!(
            "websocket upgrade failed: {}",
            String::from_utf8_lossy(status)
        )));
    }

    Ok(Ws { inner })
}

pub async fn send(ws: &mut Ws, msg: &WsMessage) -> std::io::Result<()> {
    let text = serde_json::to_string(msg).map_err(std::io::Error::other)?;
    write_frame(&mut ws.inner, 0x1, text.as_bytes()).await
}

/// Receive the next control message, replying to pings and skipping non-text frames.
pub async fn recv(ws: &mut Ws) -> std::io::Result<Option<WsMessage>> {
    let mut msg = Vec::new();
    let mut msg_is_text = false;
    loop {
        let (fin, opcode, payload) = read_frame(&mut ws.inner).await?;
        match opcode {
            // Reply to server keepalive pings immediately; a missed pong makes
            // the server drop the connection, forcing a reconnect.
            0x9 => write_frame(&mut ws.inner, 0xA, &payload).await?,
            0xA => {}             // pong
            0x8 => return Ok(None), // close
            0x0 | 0x1 | 0x2 => {
                if opcode == 0x1 {
                    msg.clear();
                    msg_is_text = true;
                } else if opcode == 0x2 {
                    msg.clear();
                    msg_is_text = false;
                }
                msg.extend_from_slice(&payload);
                if fin {
                    if msg_is_text {
                        let m: WsMessage = serde_json::from_slice(&msg).map_err(std::io::Error::other)?;
                        return Ok(Some(m));
                    }
                    msg.clear();
                }
            }
            _ => return Err(std::io::Error::other("unknown websocket opcode")),
        }
    }
}

/// Write one client frame: FIN set, masked payload (clients must mask per RFC 6455).
async fn write_frame(io: &mut Inner, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode);
    let len = payload.len();
    if len < 126 {
        frame.push(0x80 | len as u8);
    } else if len <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mut mask = [0u8; 4];
    OsRng.fill_bytes(&mut mask);
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, &x)| x ^ mask[i & 3]));
    io.write_all(&frame).await?;
    io.flush().await
}

/// Read one frame, returning (fin, opcode, unmasked payload).
async fn read_frame(io: &mut Inner) -> std::io::Result<(bool, u8, Vec<u8>)> {
    let mut h = [0u8; 2];
    io.read_exact(&mut h).await?;
    let fin = h[0] & 0x80 != 0;
    let opcode = h[0] & 0x0f;
    let masked = h[1] & 0x80 != 0;
    let len = match h[1] & 0x7f {
        126 => {
            let mut l = [0u8; 2];
            io.read_exact(&mut l).await?;
            u16::from_be_bytes(l) as usize
        }
        127 => {
            let mut l = [0u8; 8];
            io.read_exact(&mut l).await?;
            u64::from_be_bytes(l) as usize
        }
        n => n as usize,
    };
    if len > MAX_FRAME {
        return Err(std::io::Error::other("websocket frame too large"));
    }
    let mask = if masked {
        let mut m = [0u8; 4];
        io.read_exact(&mut m).await?;
        Some(m)
    } else {
        None
    };
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    if let Some(m) = mask {
        for (i, x) in payload.iter_mut().enumerate() {
            *x ^= m[i & 3];
        }
    }
    Ok((fin, opcode, payload))
}
