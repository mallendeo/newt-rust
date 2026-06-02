use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::TryRecvError;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::IpAddress;
use newt_core::proto::{topic, ExitNodeData, WgData, WsMessage};
use newt_core::sm::{Action, Event, Sm};
use newt_core::target::Target;
use crate::config::Config;
use crate::transport::{tls, token, ws};
use crate::{wg, netstack, proxy};

pub async fn run(cfg: Config) -> std::io::Result<()> {
    let tls_cfg = tls::client_config(cfg.skip_tls_verify);
    let keys = wg::generate_keys();
    let mut sm = Sm::new(keys.public_b64.clone(), concat!("rust-", env!("CARGO_PKG_VERSION")).into(), false);

    loop {
        if let Err(e) = session(&cfg, &tls_cfg, &keys, &mut sm).await {
            crate::warn!("session ended: {e}; reconnecting in 3s");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(3)) => {}
            _ = tokio::signal::ctrl_c() => { crate::info!("shutting down"); return Ok(()); }
        }
        sm = Sm::new(keys.public_b64.clone(), concat!("rust-", env!("CARGO_PKG_VERSION")).into(), false);
    }
}

/// One WebSocket session: connect, run the control + data planes until drop.
async fn session(
    cfg: &Config,
    tls_cfg: &Arc<rustls::ClientConfig>,
    keys: &wg::Keys,
    sm: &mut Sm,
) -> std::io::Result<()> {
    let jwt = token::get_token(&cfg.endpoint, &cfg.id, &cfg.secret, tls_cfg.clone()).await?;
    let mut socket = ws::connect(&cfg.endpoint, &jwt, tls_cfg.clone()).await?;
    crate::info!("websocket connected");

    let mut data: Option<DataPlane> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));

    for act in sm.step(Event::WsConnected) { exec(&mut socket, &mut data, act, cfg, keys).await?; }

    loop {
        tokio::select! {
            msg = ws::recv(&mut socket) => {
                let Some(msg) = msg? else { return Ok(()); };
                if let Some(ev) = to_event(msg) {
                    for act in sm.step(ev) { exec(&mut socket, &mut data, act, cfg, keys).await?; }
                }
            }
            _ = tick.tick() => {
                for act in sm.step(Event::Tick(1000)) { exec(&mut socket, &mut data, act, cfg, keys).await?; }
                if let Some(d) = data.as_mut() { d.send_ping().await?; }
            }
            // Data-plane progress: only armed once a tunnel exists.
            r = drive(&mut data), if data.is_some() => { r?; }
            _ = tokio::signal::ctrl_c() => { return Err(std::io::Error::other("ctrl-c")); }
        }
    }
}

fn to_event(msg: WsMessage) -> Option<Event> {
    match msg.typ.as_str() {
        topic::PING_EXIT_NODES => serde_json::from_value::<ExitNodeData>(msg.data).ok().map(Event::ExitNodes),
        topic::WG_CONNECT => serde_json::from_value::<WgData>(msg.data).ok().map(Event::WgConnect),
        topic::WG_RECONNECT => Some(Event::Reconnect),
        topic::WG_TERMINATE => Some(Event::Terminate),
        _ => None,
    }
}

async fn exec(
    socket: &mut ws::Ws,
    data: &mut Option<DataPlane>,
    act: Action,
    cfg: &Config,
    keys: &wg::Keys,
) -> std::io::Result<()> {
    match act {
        Action::Send(m) => ws::send(socket, &m).await?,
        Action::BringUp(wg_data) => { *data = Some(DataPlane::bring_up(wg_data, cfg, keys).await?); }
        Action::Teardown => { *data = None; }
        Action::Stop => return Err(std::io::Error::other("terminated by server")),
    }
    Ok(())
}

struct DataPlane {
    udp: UdpSocket,
    pump: wg::Pump,
    stack: netstack::Stack,
    listeners: Vec<Listener>,        // one per TCP listen port (pool entries)
    conns: HashMap<SocketHandle, Bridge>,
    udp_buf: Vec<u8>,
    server_ip: [u8; 4],              // exit node tunnel IP, pinged to keep the site online
    tunnel_ip4: [u8; 4],             // our tunnel IP, ping source
    ping_seq: u16,
}

struct Listener { port: u16, target: String, handle: SocketHandle }

/// Per-connection state owned by the tunnel loop. `pending` holds at most one
/// chunk of target->smoltcp bytes that did not fit in the smoltcp tx buffer yet,
/// so we never pull more from the bridge than smoltcp can accept (backpressure).
struct Bridge {
    conn: proxy::Conn,
    pending: Vec<u8>,
    target_done: bool,
}

impl Bridge {
    fn new(conn: proxy::Conn) -> Self {
        Bridge { conn, pending: Vec::new(), target_done: false }
    }
}

const TCP_RX: usize = 4096;
const TCP_TX: usize = 4096;

impl DataPlane {
    async fn bring_up(wg_data: WgData, cfg: &Config, keys: &wg::Keys) -> std::io::Result<Self> {
        // WireGuard handshake goes to the exit node's listen port, carried in
        // `endpoint` as host:listenPort. relayPort is for olm clients, not newt.
        let (host, port) = wg_data.endpoint.rsplit_once(':')
            .and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h, p)))
            .ok_or_else(|| std::io::Error::other("bad endpoint"))?;
        let endpoint: std::net::SocketAddr = tokio::net::lookup_host((host, port)).await?
            .next().ok_or_else(|| std::io::Error::other("resolve endpoint"))?;
        let udp = UdpSocket::bind(("0.0.0.0", 0)).await?;
        udp.connect(endpoint).await?;

        let peer_pub = wg::public_from_b64(&wg_data.public_key).map_err(std::io::Error::other)?;
        let mut pump = wg::Pump::new(keys.secret.clone(), peer_pub, cfg.mtu);

        // Kick the handshake now; update_timers retransmits if the first init is lost.
        if let Some(init) = pump.initiate_handshake() {
            let n = udp.send(&init).await?;
            crate::info!("wireguard handshake sent to {endpoint} ({n} bytes)");
        }

        let tunnel_ip: IpAddress = wg_data.tunnel_ip.parse().map_err(|_| std::io::Error::other("bad tunnelIP"))?;
        let mut stack = netstack::Stack::new(tunnel_ip, cfg.mtu, SmolInstant::ZERO);

        // Create one listening socket per TCP target.
        let mut listeners = Vec::new();
        for t in wg_data.targets.tcp.iter().filter_map(|s| Target::parse(s)) {
            let handle = add_listener(&mut stack, t.listen_port);
            listeners.push(Listener { port: t.listen_port, target: format!("{}:{}", t.host, t.target_port), handle });
        }
        crate::info!("tunnel up: {} tcp target(s)", listeners.len());

        let server_ip: std::net::Ipv4Addr = wg_data.server_ip.parse()
            .map_err(|_| std::io::Error::other("bad serverIP"))?;
        let tunnel_ip4: std::net::Ipv4Addr = wg_data.tunnel_ip.parse()
            .map_err(|_| std::io::Error::other("bad tunnelIP"))?;

        Ok(DataPlane {
            udp, pump, stack, listeners,
            conns: HashMap::new(), udp_buf: vec![0u8; cfg.mtu.max(1500) + 64],
            server_ip: server_ip.octets(), tunnel_ip4: tunnel_ip4.octets(), ping_seq: 0,
        })
    }

    /// Send an ICMP echo to the exit node's tunnel IP. This drives the WireGuard
    /// handshake and produces the inbound traffic the exit node counts to mark the
    /// site online; without it a passive newt with no targets never reports as up.
    async fn send_ping(&mut self) -> std::io::Result<()> {
        self.ping_seq = self.ping_seq.wrapping_add(1);
        let pkt = icmp_echo(self.tunnel_ip4, self.server_ip, 1, self.ping_seq);
        if let Some(dg) = self.pump.encapsulate(&pkt) {
            self.udp.send(&dg).await?;
        }
        Ok(())
    }

    async fn step_io(&mut self) -> std::io::Result<()> {
        // 1. Receive inbound WireGuard datagrams (with a short timeout fallback).
        tokio::select! {
            r = self.udp.recv(&mut self.udp_buf) => {
                let n = r?;
                let datagram = self.udp_buf[..n].to_vec();
                match self.pump.decapsulate(&datagram) {
                    wg::Inbound::Packet(p) => self.stack.device.rx.push_back(p),
                    wg::Inbound::Network(b) => { let _ = self.udp.send(&b).await; }
                    wg::Inbound::Nothing => {}
                }
                loop {
                    match self.pump.drain() {
                        wg::Inbound::Packet(p) => self.stack.device.rx.push_back(p),
                        wg::Inbound::Network(b) => { let _ = self.udp.send(&b).await; }
                        wg::Inbound::Nothing => break,
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }

        // 2. Poll smoltcp; encapsulate any outbound IP packets.
        let outbound = self.stack.poll(SmolInstant::ZERO);
        for pkt in outbound {
            if let Some(dg) = self.pump.encapsulate(&pkt) { let _ = self.udp.send(&dg).await; }
        }

        // 3. WireGuard timers.
        if let Some(dg) = self.pump.update_timers() { let _ = self.udp.send(&dg).await; }

        // 4. Service listeners: detect newly-established connections, wire bridges.
        self.accept_new();

        // 5. Pump bytes between smoltcp sockets and their bridge tasks.
        self.shuttle().await;
        Ok(())
    }

    fn accept_new(&mut self) {
        // Find listeners whose socket just became active and have no bridge yet.
        let mut promoted: Vec<(usize, u16)> = Vec::new();
        for (i, l) in self.listeners.iter().enumerate() {
            let s = self.stack.sockets.get::<tcp::Socket>(l.handle);
            if s.is_active() && !self.conns.contains_key(&l.handle) {
                promoted.push((i, l.port));
            }
        }
        // Promote in reverse index order so swap_remove keeps lower indices valid.
        // The promoted listening socket BECOMES the connection socket; we replace
        // its listener entry with a fresh LISTEN socket on the same port so the
        // listeners Vec keeps exactly one entry per port.
        for (i, port) in promoted.into_iter().rev() {
            let l = self.listeners.swap_remove(i);
            let conn = proxy::spawn_tcp(l.target.clone());
            self.conns.insert(l.handle, Bridge::new(conn));
            let handle = add_listener(&mut self.stack, port);
            self.listeners.push(Listener { port, target: l.target, handle });
        }
    }

    async fn shuttle(&mut self) {
        let handles: Vec<SocketHandle> = self.conns.keys().copied().collect();
        for h in handles {
            // smoltcp -> target: only consume bytes we can actually hand off, so a
            // full bridge channel backpressures the TCP window instead of losing data.
            loop {
                let permit = match self.conns.get(&h) {
                    Some(b) => match b.conn.to_target.try_reserve() {
                        Ok(p) => p,
                        Err(_) => break, // channel full or closed: leave bytes in smoltcp
                    },
                    None => break,
                };
                let s = self.stack.sockets.get_mut::<tcp::Socket>(h);
                if !s.can_recv() { break; }
                let chunk = s.recv(|buf| { let v = buf.to_vec(); (v.len(), v) }).unwrap_or_default();
                if chunk.is_empty() { break; }
                permit.send(chunk);
            }

            // target -> smoltcp: keep at most one leftover chunk pending; only pull a
            // new chunk when the previous one is fully flushed. A Disconnected channel
            // means the target closed -> mark target_done so we can FIN.
            if let Some(b) = self.conns.get_mut(&h) {
                if b.pending.is_empty() {
                    match b.conn.from_target.try_recv() {
                        Ok(d) => b.pending = d,
                        Err(TryRecvError::Empty) => {}
                        Err(TryRecvError::Disconnected) => b.target_done = true,
                    }
                }
            }
            // Flush pending into smoltcp, keeping any unsent remainder.
            if let Some(b) = self.conns.get_mut(&h) {
                if !b.pending.is_empty() {
                    let s = self.stack.sockets.get_mut::<tcp::Socket>(h);
                    if s.can_send() {
                        let sent = s.send_slice(&b.pending).unwrap_or(0);
                        b.pending.drain(..sent);
                    }
                }
            }
            // Half-close: target finished and everything is flushed -> send FIN.
            let (target_done, pending_empty) = match self.conns.get(&h) {
                Some(b) => (b.target_done, b.pending.is_empty()),
                None => (false, true),
            };
            if target_done && pending_empty {
                let s = self.stack.sockets.get_mut::<tcp::Socket>(h);
                if s.is_open() { s.close(); }
            }
            // Reap fully-closed sockets: drop the bridge AND free the smoltcp socket.
            if !self.stack.sockets.get::<tcp::Socket>(h).is_open() {
                self.conns.remove(&h);
                self.stack.sockets.remove(h);
            }
        }
    }
}

/// Build an IPv4 ICMP echo request packet (matches the upstream newt keepalive ping).
fn icmp_echo(src: [u8; 4], dst: [u8; 4], ident: u16, seq: u16) -> Vec<u8> {
    let payload = b"newtping";
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.extend_from_slice(&[8, 0, 0, 0]); // type=echo request, code=0, checksum placeholder
    icmp.extend_from_slice(&ident.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let c = checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());

    let total = 20 + icmp.len();
    let mut ip = Vec::with_capacity(total);
    ip.extend_from_slice(&[0x45, 0x00]);                  // version/IHL, DSCP/ECN
    ip.extend_from_slice(&(total as u16).to_be_bytes());  // total length
    ip.extend_from_slice(&[0, 0, 0x40, 0x00]);            // id, flags=DF
    ip.extend_from_slice(&[64, 1, 0, 0]);                 // ttl, proto=ICMP, checksum placeholder
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// Internet checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks { sum += u16::from_be_bytes([c[0], c[1]]) as u32; }
    if let [last] = chunks.remainder() { sum += (*last as u32) << 8; }
    while (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

fn add_listener(stack: &mut netstack::Stack, port: u16) -> SocketHandle {
    let s = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; TCP_RX]),
        tcp::SocketBuffer::new(vec![0u8; TCP_TX]),
    );
    let handle = stack.sockets.add(s);
    stack.sockets.get_mut::<tcp::Socket>(handle).listen(port).ok();
    handle
}

async fn drive(data: &mut Option<DataPlane>) -> std::io::Result<()> {
    match data { Some(d) => d.step_io().await, None => { futures_util::future::pending::<()>().await; Ok(()) } }
}
