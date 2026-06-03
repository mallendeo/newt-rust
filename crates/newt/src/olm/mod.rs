//! Client (olm) role: register as a Pangolin client, bring up a multi-peer
//! WireGuard data plane to the sites it may reach, and expose those remote
//! resources to the host (transparent kernel routing or userspace forwards).

pub mod proto;
pub mod router;
pub mod holepunch;
pub mod userspace;
pub mod backend;
#[cfg(target_os = "linux")]
pub mod tun;
#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod kernel;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use serde_json::json;
use tokio::net::UdpSocket;
use newt_core::proto::WsMessage;
use crate::config::ClientRun;
use crate::transport::{tls, token, ws};
use crate::wg;
use backend::Backend;
use holepunch::HolePunch;
use router::{Cidr, Out, Router};

const VERSION: &str = concat!("rust-", env!("CARGO_PKG_VERSION"));

struct DataPlane {
    router: Router,
    backend: Backend,
}

pub async fn run(cfg: ClientRun) -> std::io::Result<()> {
    let tls_cfg = tls::client_config(cfg.skip_tls_verify);
    let keys = wg::generate_keys();
    loop {
        if let Err(e) = session(&cfg, &tls_cfg, &keys).await {
            crate::warn!("olm session ended: {e}; reconnecting in 3s");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn session(
    cfg: &ClientRun,
    tls_cfg: &Arc<rustls::ClientConfig>,
    keys: &wg::Keys,
) -> std::io::Result<()> {
    // get-token also carries the exit nodes and the hole-punch token.
    let data = token::get_token_data(
        &cfg.endpoint,
        "olm",
        &json!({ "olmId": cfg.id, "secret": cfg.secret, "userToken": cfg.user_token, "orgId": cfg.org_id }),
        tls_cfg.clone(),
    ).await?;
    let tok = data["token"].as_str()
        .ok_or_else(|| std::io::Error::other("no token in olm get-token response"))?
        .to_string();
    let exit_nodes = parse_exit_nodes(&data).await;

    let mut socket = ws::connect(&cfg.endpoint, &tok, "olm", tls_cfg.clone()).await?;
    crate::info!("olm websocket connected");

    let udp = UdpSocket::bind(("0.0.0.0", 0)).await?;
    let mut hp = HolePunch::new(cfg.id.clone(), keys.public_b64.clone(), tok);
    hp.set_nodes(exit_nodes);

    let mut dp: Option<DataPlane> = None;
    let mut buf = vec![0u8; cfg.mtu.max(1500) + 64];
    let mut tick = tokio::time::interval(Duration::from_secs(1));

    ws::send(&mut socket, &register_msg(cfg, &keys.public_b64)).await?;

    loop {
        tokio::select! {
            msg = ws::recv(&mut socket) => {
                let Some(msg) = msg? else { return Ok(()); };
                if handle_message(msg, &mut dp, cfg, keys, &udp).await? { return Ok(()); }
            }
            _ = tick.tick() => {
                if dp.is_none() {
                    ws::send(&mut socket, &register_msg(cfg, &keys.public_b64)).await?;
                }
                for (b, e) in hp.datagrams() { udp.send_to(&b, e).await?; }
                if let Some(d) = dp.as_mut() {
                    for (b, e) in d.router.tick() { udp.send_to(&b, e).await?; }
                }
            }
            r = udp.recv_from(&mut buf) => {
                let (n, _src) = r?;
                if let Some(d) = dp.as_mut() {
                    for out in d.router.handle_inbound(&buf[..n]) {
                        match out {
                            Out::ToHost(p) => d.backend.deliver_inbound(&p).await?,
                            Out::ToNet(b, e) => { udp.send_to(&b, e).await?; }
                        }
                    }
                }
            }
            r = drive(&mut dp), if dp.is_some() => {
                let pkts = r?;
                if let Some(d) = dp.as_mut() {
                    for pkt in pkts {
                        if let Some((b, e)) = d.router.route_outbound(&pkt) { udp.send_to(&b, e).await?; }
                    }
                }
            }
        }
    }
}

/// Handle one control message. Returns Ok(true) when the session should end.
async fn handle_message(
    msg: WsMessage,
    dp: &mut Option<DataPlane>,
    cfg: &ClientRun,
    keys: &wg::Keys,
    udp: &UdpSocket,
) -> std::io::Result<bool> {
    match msg.typ.as_str() {
        proto::topic::CONNECT => {
            let wg: proto::WgData = serde_json::from_value(msg.data).unwrap_or_default();
            let (d, inits) = build_dataplane(cfg, keys, wg).await?;
            for (b, e) in inits { udp.send_to(&b, e).await?; }
            crate::info!("olm connected: {} peer(s)", d.router.peer_count());
            *dp = Some(d);
        }
        proto::topic::PEER_ADD | proto::topic::PEER_UPDATE => {
            if let (Some(d), Ok(site)) = (dp.as_mut(), serde_json::from_value::<proto::SiteConfig>(msg.data)) {
                if let Some((b, e)) = upsert_site(d, &site).await { udp.send_to(&b, e).await?; }
            }
        }
        proto::topic::PEER_REMOVE => {
            if let (Some(d), Ok(r)) = (dp.as_mut(), serde_json::from_value::<proto::PeerRemove>(msg.data)) {
                d.router.remove_peer(r.site_id);
                crate::info!("olm peer {} removed", r.site_id);
            }
        }
        proto::topic::PEER_RELAY => {
            if let (Some(d), Ok(r)) = (dp.as_mut(), serde_json::from_value::<proto::PeerRelay>(msg.data)) {
                if let Ok(ep) = resolve(&r.relay_endpoint).await { d.router.set_endpoint(r.site_id, ep); }
            }
        }
        proto::topic::PEER_UNRELAY => {
            if let (Some(d), Ok(r)) = (dp.as_mut(), serde_json::from_value::<proto::PeerUnrelay>(msg.data)) {
                if let Ok(ep) = resolve(&r.endpoint).await { d.router.set_endpoint(r.site_id, ep); }
            }
        }
        proto::topic::PEER_DATA_ADD => {
            if let (Some(d), Ok(r)) = (dp.as_mut(), serde_json::from_value::<proto::PeerData>(msg.data)) {
                let cidrs = parse_cidrs(&r.remote_subnets);
                d.router.add_cidrs(r.site_id, cidrs.clone());
                d.backend.add_routes(&cidrs)?;
            }
        }
        proto::topic::PEER_DATA_REMOVE => {
            if let (Some(d), Ok(r)) = (dp.as_mut(), serde_json::from_value::<proto::PeerData>(msg.data)) {
                d.router.remove_cidrs(r.site_id, &parse_cidrs(&r.remote_subnets));
            }
        }
        proto::topic::SYNC => {
            if let (Some(d), Ok(s)) = (dp.as_mut(), serde_json::from_value::<proto::SyncData>(msg.data)) {
                for site in &s.sites {
                    if let Some((b, e)) = upsert_site(d, site).await { udp.send_to(&b, e).await?; }
                }
            }
        }
        proto::topic::ERROR => {
            let e: proto::ErrorData = serde_json::from_value(msg.data).unwrap_or_default();
            crate::error!("olm error [{}]: {}", e.code, e.message);
        }
        proto::topic::TERMINATE => {
            let e: proto::ErrorData = serde_json::from_value(msg.data).unwrap_or_default();
            crate::warn!("olm terminated [{}]: {}", e.code, e.message);
            return Ok(true);
        }
        _ => {}
    }
    Ok(false)
}

async fn build_dataplane(
    cfg: &ClientRun,
    keys: &wg::Keys,
    wg: proto::WgData,
) -> std::io::Result<(DataPlane, Vec<(Vec<u8>, SocketAddr)>)> {
    let tunnel_ip: IpAddr = wg.tunnel_ip.split('/').next().unwrap_or(&wg.tunnel_ip)
        .parse().map_err(|_| std::io::Error::other("bad olm tunnelIP"))?;
    let mut router = Router::new(keys.secret.clone(), cfg.mtu);
    let mut backend = Backend::new(cfg, tunnel_ip).await?;

    let mut inits = Vec::new();
    let mut all_cidrs = Vec::new();
    for site in &wg.sites {
        if site.public_key.is_empty() { continue; }
        let Ok(ep) = resolve(site.wg_endpoint()).await else {
            crate::warn!("olm: cannot resolve endpoint for site {}", site.site_id);
            continue;
        };
        let cidrs: Vec<Cidr> = site.routed_cidrs().filter_map(|s| Cidr::parse(s)).collect();
        if let Some(init) = router.upsert_peer(site.site_id, &site.public_key, ep, cidrs.clone()) {
            inits.push(init);
        }
        all_cidrs.extend(cidrs);
    }
    backend.add_routes(&all_cidrs)?;
    Ok((DataPlane { router, backend }, inits))
}

/// Add or update one site in a running data plane; returns a handshake
/// initiation to send if the peer was (re)created.
async fn upsert_site(dp: &mut DataPlane, site: &proto::SiteConfig) -> Option<(Vec<u8>, SocketAddr)> {
    if site.public_key.is_empty() { return None; }
    let ep = resolve(site.wg_endpoint()).await.ok()?;
    let cidrs: Vec<Cidr> = site.routed_cidrs().filter_map(|s| Cidr::parse(s)).collect();
    let init = dp.router.upsert_peer(site.site_id, &site.public_key, ep, cidrs.clone());
    let _ = dp.backend.add_routes(&cidrs);
    init
}

fn parse_cidrs(specs: &[String]) -> Vec<Cidr> {
    specs.iter().filter_map(|s| Cidr::parse(s)).collect()
}

fn register_msg(cfg: &ClientRun, public_key_b64: &str) -> WsMessage {
    WsMessage {
        typ: proto::topic::REGISTER.into(),
        data: json!({
            "publicKey": public_key_b64,
            "relay": true,
            "olmVersion": VERSION,
            "olmAgent": "newt-rust",
            "orgId": cfg.org_id,
            "userToken": cfg.user_token,
            "fingerprint": {},
            "postures": {},
        }),
        config_version: None,
    }
}

async fn resolve(hostport: &str) -> std::io::Result<SocketAddr> {
    tokio::net::lookup_host(hostport).await?
        .next().ok_or_else(|| std::io::Error::other(format!("resolve {hostport}")))
}

/// Parse `data.exitNodes` and resolve each to its hole-punch (relay) address.
async fn parse_exit_nodes(data: &serde_json::Value) -> Vec<holepunch::ExitNode> {
    let mut out = Vec::new();
    let Some(arr) = data["exitNodes"].as_array() else { return out; };
    for n in arr {
        let endpoint = n["endpoint"].as_str().unwrap_or_default();
        let server_pub = n["publicKey"].as_str().unwrap_or_default().to_string();
        let mut relay_port = n["relayPort"].as_u64().unwrap_or(0) as u16;
        if relay_port == 0 { relay_port = 21820; }
        let host = endpoint.rsplit_once(':').map(|(h, _)| h).unwrap_or(endpoint);
        if host.is_empty() || server_pub.is_empty() { continue; }
        if let Ok(mut addrs) = tokio::net::lookup_host((host, relay_port)).await {
            if let Some(addr) = addrs.next() {
                out.push(holepunch::ExitNode { addr, server_pub });
            }
        }
    }
    out
}

async fn drive(dp: &mut Option<DataPlane>) -> std::io::Result<Vec<Vec<u8>>> {
    match dp {
        Some(d) => d.backend.drive().await,
        None => { futures_util::future::pending::<()>().await; Ok(Vec::new()) }
    }
}
