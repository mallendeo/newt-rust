use std::sync::Arc;
use std::time::Duration;
use newt_core::proto::{topic, ExitNodeData, WgData, WsMessage};
use newt_core::sm::{Action, Event, Sm};
use crate::config::Config;
use crate::transport::{tls, token, ws};
use crate::wg;

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

// Temporary stub; replaced by the real data plane in Task H2.
struct DataPlane;
impl DataPlane {
    async fn bring_up(_wg: WgData, _cfg: &Config, _keys: &wg::Keys) -> std::io::Result<Self> { Ok(DataPlane) }
}
async fn drive(_data: &mut Option<DataPlane>) -> std::io::Result<()> {
    futures_util::future::pending::<()>().await; Ok(())
}
