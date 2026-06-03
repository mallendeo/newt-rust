use newt_lib::config::{ClientRun, Config, SiteRun};
use newt_lib::{olm, tunnel};

/// Resolve on SIGINT or SIGTERM so `docker stop`/`restart` exits promptly
/// instead of waiting for the kill timeout.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut intr = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = intr.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match Config::from_sources(&|k| std::env::var(k).ok(), &args) {
        Ok(c) => c,
        Err(e) => { eprintln!("config error: {e}"); std::process::exit(2); }
    };
    newt_lib::log::set_level(&cfg.log_level);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let result = rt.block_on(async {
        let Config { site, client, .. } = cfg;
        tokio::select! {
            r = run_roles(site, client) => r,
            _ = shutdown_signal() => { newt_lib::info!("shutting down"); Ok(()) }
        }
    });
    if let Err(e) = result {
        newt_lib::error!("fatal: {e}");
        std::process::exit(1);
    }
}

/// Run the active role(s). With both active they run concurrently; if either
/// exits the process exits so a supervisor can restart cleanly.
async fn run_roles(site: Option<SiteRun>, client: Option<ClientRun>) -> std::io::Result<()> {
    match (site, client) {
        (Some(s), None) => tunnel::run(s).await,
        (None, Some(c)) => olm::run(c).await,
        (Some(s), Some(c)) => tokio::select! {
            r = tunnel::run(s) => r,
            r = olm::run(c) => r,
        },
        (None, None) => Ok(()),
    }
}
