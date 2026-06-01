use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
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
    conns: HashMap<SocketHandle, proxy::Conn>,
    udp_buf: Vec<u8>,
}

struct Listener { port: u16, target: String, handle: SocketHandle }

const TCP_RX: usize = 4096;
const TCP_TX: usize = 4096;

impl DataPlane {
    async fn bring_up(wg_data: WgData, cfg: &Config, keys: &wg::Keys) -> std::io::Result<Self> {
        let mut relay = wg_data.relay_port; if relay == 0 { relay = 21820; }
        // Resolve endpoint host; WireGuard sends to the relay UDP port.
        let host = wg_data.endpoint.rsplit_once(':').map(|x| x.0).unwrap_or(&wg_data.endpoint);
        let endpoint: std::net::SocketAddr = tokio::net::lookup_host((host, relay)).await?
            .next().ok_or_else(|| std::io::Error::other("resolve endpoint"))?;
        let udp = UdpSocket::bind(("0.0.0.0", 0)).await?;
        udp.connect(endpoint).await?;

        let peer_pub = wg::public_from_b64(&wg_data.public_key).map_err(std::io::Error::other)?;
        let pump = wg::Pump::new(keys.secret.clone(), peer_pub, cfg.mtu);

        let tunnel_ip: IpAddress = wg_data.tunnel_ip.parse().map_err(|_| std::io::Error::other("bad tunnelIP"))?;
        let mut stack = netstack::Stack::new(tunnel_ip, cfg.mtu, SmolInstant::ZERO);

        // Create one listening socket per TCP target.
        let mut listeners = Vec::new();
        for t in wg_data.targets.tcp.iter().filter_map(|s| Target::parse(s)) {
            let handle = add_listener(&mut stack, t.listen_port);
            listeners.push(Listener { port: t.listen_port, target: format!("{}:{}", t.host, t.target_port), handle });
        }
        crate::info!("tunnel up: {} tcp target(s)", listeners.len());

        Ok(DataPlane {
            udp, pump, stack, listeners,
            conns: HashMap::new(), udp_buf: vec![0u8; cfg.mtu.max(1500) + 64],
        })
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
        let mut replacements: Vec<(usize, u16)> = Vec::new();
        for (i, l) in self.listeners.iter().enumerate() {
            let s = self.stack.sockets.get::<tcp::Socket>(l.handle);
            if s.is_active() && !self.conns.contains_key(&l.handle) {
                let conn = proxy::spawn_tcp(l.target.clone());
                self.conns.insert(l.handle, conn);
                replacements.push((i, l.port));
            }
        }
        // Add a fresh listening socket per port that just got consumed.
        for (i, port) in replacements {
            let handle = add_listener(&mut self.stack, port);
            let target = self.listeners[i].target.clone();
            self.listeners.push(Listener { port, target, handle });
        }
    }

    async fn shuttle(&mut self) {
        let handles: Vec<SocketHandle> = self.conns.keys().copied().collect();
        for h in handles {
            // smoltcp -> target
            loop {
                let s = self.stack.sockets.get_mut::<tcp::Socket>(h);
                if !s.can_recv() { break; }
                let chunk = s.recv(|buf| { let v = buf.to_vec(); (v.len(), v) }).unwrap_or_default();
                if chunk.is_empty() { break; }
                if let Some(c) = self.conns.get(&h) { let _ = c.to_target.try_send(chunk); }
            }
            // target -> smoltcp
            if let Some(c) = self.conns.get_mut(&h) {
                while let Ok(data) = c.from_target.try_recv() {
                    let s = self.stack.sockets.get_mut::<tcp::Socket>(h);
                    if s.can_send() { let _ = s.send_slice(&data); }
                }
            }
            // Close handling: if smoltcp socket closed, drop the bridge.
            let s = self.stack.sockets.get::<tcp::Socket>(h);
            if !s.is_open() { self.conns.remove(&h); }
        }
    }
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
