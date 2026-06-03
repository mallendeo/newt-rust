//! Userspace client backend: a smoltcp netstack originates connections to remote
//! resources; local TCP listeners (forwards) bridge host apps into the tunnel.
//! No kernel TUN and no privileges, so it runs anywhere the binary runs.

use std::collections::HashMap;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::error::TryRecvError;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::IpAddress;
use crate::config::Forward;
use crate::netstack::Stack;
use crate::proxy;

const TCP_RX: usize = 8192;
const TCP_TX: usize = 8192;

struct ForwardListener {
    listener: TcpListener,
    dest: IpAddress,
    dest_port: u16,
}

struct Bridge {
    conn: proxy::Conn,
    pending: Vec<u8>,
    app_done: bool,
}

pub struct UserspaceBackend {
    stack: Stack,
    forwards: Vec<ForwardListener>,
    conns: HashMap<SocketHandle, Bridge>,
    next_port: u16,
    start: tokio::time::Instant,
}

impl UserspaceBackend {
    pub async fn new(tunnel_ip: IpAddress, mtu: usize, forwards: &[Forward]) -> std::io::Result<Self> {
        let mut stack = Stack::new(tunnel_ip, mtu, SmolInstant::ZERO);
        // Default routes so packets to off-link remote IPs are emitted to the
        // device (the gateway is a placeholder; there is no link layer).
        stack.add_default_routes(
            smoltcp::wire::Ipv4Address::new(0, 0, 0, 1),
            smoltcp::wire::Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1),
        );

        let mut fl = Vec::new();
        for f in forwards {
            let dest: std::net::IpAddr = f.dest_host.parse().map_err(|_| {
                std::io::Error::other(format!("forward dest must be an IP address: {}", f.dest_host))
            })?;
            let listener = TcpListener::bind(("127.0.0.1", f.listen_port)).await?;
            crate::info!("forward 127.0.0.1:{} -> {}:{} via tunnel", f.listen_port, f.dest_host, f.dest_port);
            fl.push(ForwardListener { listener, dest: to_smol(dest), dest_port: f.dest_port });
        }

        Ok(UserspaceBackend {
            stack,
            forwards: fl,
            conns: HashMap::new(),
            next_port: 20000,
            start: tokio::time::Instant::now(),
        })
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_millis(self.start.elapsed().as_millis() as i64)
    }

    pub fn deliver_inbound(&mut self, pkt: &[u8]) {
        self.stack.device.rx.push_back(pkt.to_vec());
    }

    /// Accept at most one new local connection, poll smoltcp, shuttle bytes, and
    /// return outbound IP packets to encrypt. Awaits up to ~20ms (or until a
    /// listener accepts) so the caller's select loop can interleave inbound
    /// delivery between calls.
    pub async fn drive(&mut self) -> std::io::Result<Vec<Vec<u8>>> {
        if let Some((stream, dest, port)) = self.next_accept().await? {
            self.open_outgoing(dest, port, stream);
        }
        let now = self.now();
        let out = self.stack.poll(now);
        self.shuttle().await;
        Ok(out)
    }

    async fn next_accept(&self) -> std::io::Result<Option<(TcpStream, IpAddress, u16)>> {
        if self.forwards.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
            return Ok(None);
        }
        let accepts = futures_util::future::select_all(
            self.forwards.iter().map(|f| Box::pin(f.listener.accept())),
        );
        tokio::select! {
            (res, idx, _) = accepts => {
                let (stream, _peer) = res?;
                Ok(Some((stream, self.forwards[idx].dest, self.forwards[idx].dest_port)))
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => Ok(None),
        }
    }

    fn open_outgoing(&mut self, dest: IpAddress, dest_port: u16, stream: TcpStream) {
        let local_port = self.alloc_port();
        let sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_RX]),
            tcp::SocketBuffer::new(vec![0u8; TCP_TX]),
        );
        let handle = self.stack.sockets.add(sock);
        if let Err(e) = self.stack.connect(handle, (dest, dest_port), local_port) {
            crate::debug!("smoltcp connect to {dest}:{dest_port} failed: {e:?}");
            self.stack.sockets.remove(handle);
            return;
        }
        self.conns.insert(handle, Bridge {
            conn: proxy::bridge_stream(stream),
            pending: Vec::new(),
            app_done: false,
        });
    }

    fn alloc_port(&mut self) -> u16 {
        let p = self.next_port;
        self.next_port = if self.next_port >= 60000 { 20000 } else { self.next_port + 1 };
        p
    }

    /// Move bytes between each smoltcp socket and its local bridge. Mirrors the
    /// site proxy's shuttle, oriented for an origin connection: bytes received
    /// from the remote go to the local app; bytes from the local app go out.
    async fn shuttle(&mut self) {
        let handles: Vec<SocketHandle> = self.conns.keys().copied().collect();
        for h in handles {
            // remote -> local app: only consume what the bridge can take.
            loop {
                let permit = match self.conns.get(&h) {
                    Some(b) => match b.conn.to_target.try_reserve() {
                        Ok(p) => p,
                        Err(_) => break,
                    },
                    None => break,
                };
                let s = self.stack.sockets.get_mut::<tcp::Socket>(h);
                if !s.can_recv() { break; }
                let chunk = s.recv(|buf| { let v = buf.to_vec(); (v.len(), v) }).unwrap_or_default();
                if chunk.is_empty() { break; }
                permit.send(chunk);
            }

            // local app -> remote: keep at most one pending chunk.
            if let Some(b) = self.conns.get_mut(&h) {
                if b.pending.is_empty() {
                    match b.conn.from_target.try_recv() {
                        Ok(d) => b.pending = d,
                        Err(TryRecvError::Empty) => {}
                        Err(TryRecvError::Disconnected) => b.app_done = true,
                    }
                }
            }
            if let Some(b) = self.conns.get_mut(&h) {
                if !b.pending.is_empty() {
                    let s = self.stack.sockets.get_mut::<tcp::Socket>(h);
                    if s.can_send() {
                        let sent = s.send_slice(&b.pending).unwrap_or(0);
                        b.pending.drain(..sent);
                    }
                }
            }
            // Half-close once the app finished and everything is flushed.
            let (app_done, pending_empty) = match self.conns.get(&h) {
                Some(b) => (b.app_done, b.pending.is_empty()),
                None => (false, true),
            };
            if app_done && pending_empty {
                let s = self.stack.sockets.get_mut::<tcp::Socket>(h);
                if s.is_open() { s.close(); }
            }
            // Reap closed sockets.
            if !self.stack.sockets.get::<tcp::Socket>(h).is_open() {
                self.conns.remove(&h);
                self.stack.sockets.remove(h);
            }
        }
    }
}

pub(crate) fn to_smol(ip: std::net::IpAddr) -> IpAddress {
    match ip {
        std::net::IpAddr::V4(a) => smoltcp::wire::Ipv4Address::from(a).into(),
        std::net::IpAddr::V6(a) => smoltcp::wire::Ipv6Address::from(a).into(),
    }
}
