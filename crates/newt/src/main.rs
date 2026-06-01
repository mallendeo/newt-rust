mod config;
mod log;
mod transport;
mod wg;
mod netstack;
mod proxy;
mod tunnel;

use config::Config;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match Config::from_sources(&|k| std::env::var(k).ok(), &args) {
        Ok(c) => c,
        Err(e) => { eprintln!("config error: {e}"); std::process::exit(2); }
    };
    log::set_level(&cfg.log_level);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    if let Err(e) = rt.block_on(tunnel::run(cfg)) {
        error!("fatal: {e}");
        std::process::exit(1);
    }
}
