use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub endpoint: String,
    pub id: String,
    pub secret: String,
    pub mtu: usize,
    pub dns: String,
    pub log_level: String,
    pub ping_interval: Duration,
    pub udp_idle_timeout: Duration,
    pub skip_tls_verify: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            endpoint: String::new(),
            id: String::new(),
            secret: String::new(),
            mtu: 1280,
            dns: "9.9.9.9".into(),
            log_level: "INFO".into(),
            ping_interval: Duration::from_secs(15),
            udp_idle_timeout: Duration::from_secs(90),
            skip_tls_verify: false,
        }
    }
}

impl Config {
    /// Build from (env_lookup, args). `env` maps NAME->value; `args` is the CLI
    /// flag list (without argv[0]). CLI overrides env.
    pub fn from_sources(
        env: &dyn Fn(&str) -> Option<String>,
        args: &[String],
    ) -> Result<Config, String> {
        let mut c = Config::default();
        if let Some(v) = env("PANGOLIN_ENDPOINT") { c.endpoint = v; }
        if let Some(v) = env("NEWT_ID") { c.id = v; }
        if let Some(v) = env("NEWT_SECRET") { c.secret = v; }
        if let Some(v) = env("MTU") { c.mtu = v.parse().map_err(|_| "bad MTU")?; }
        if let Some(v) = env("DNS") { c.dns = v; }
        if let Some(v) = env("LOG_LEVEL") { c.log_level = v; }
        if let Some(v) = env("PING_INTERVAL") { c.ping_interval = parse_secs(&v)?; }
        if let Some(v) = env("NEWT_UDP_PROXY_IDLE_TIMEOUT") { c.udp_idle_timeout = parse_secs(&v)?; }
        if let Some(v) = env("SKIP_TLS_VERIFY") { c.skip_tls_verify = truthy(&v); }

        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "-endpoint" | "--endpoint" => c.endpoint = next(&mut it, a)?,
                "-id" | "--id" => c.id = next(&mut it, a)?,
                "-secret" | "--secret" => c.secret = next(&mut it, a)?,
                "-mtu" | "--mtu" => c.mtu = next(&mut it, a)?.parse().map_err(|_| "bad --mtu")?,
                "-dns" | "--dns" => c.dns = next(&mut it, a)?,
                "-log-level" | "--log-level" => c.log_level = next(&mut it, a)?,
                "-skip-tls-verify" | "--skip-tls-verify" => c.skip_tls_verify = true,
                other => return Err(format!("unknown flag: {other}")),
            }
        }
        if c.endpoint.is_empty() || c.id.is_empty() || c.secret.is_empty() {
            return Err("endpoint, id and secret are required".into());
        }
        Ok(c)
    }
}

fn next(it: &mut std::slice::Iter<String>, flag: &str) -> Result<String, String> {
    it.next().cloned().ok_or_else(|| format!("missing value for {flag}"))
}
fn parse_secs(v: &str) -> Result<Duration, String> {
    let v = v.trim_end_matches('s');
    v.parse::<u64>().map(Duration::from_secs).map_err(|_| "bad duration".into())
}
fn truthy(v: &str) -> bool { matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes") }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_overrides_env_and_requires_creds() {
        let env = |k: &str| match k {
            "PANGOLIN_ENDPOINT" => Some("https://env".into()),
            "NEWT_ID" => Some("envid".into()),
            "NEWT_SECRET" => Some("envsecret".into()),
            _ => None,
        };
        let args = vec!["--endpoint".into(), "https://cli".into()];
        let c = Config::from_sources(&env, &args).unwrap();
        assert_eq!(c.endpoint, "https://cli");
        assert_eq!(c.id, "envid");
    }

    #[test]
    fn missing_creds_errors() {
        let env = |_: &str| None;
        assert!(Config::from_sources(&env, &[]).is_err());
    }
}
