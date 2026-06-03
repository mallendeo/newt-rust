use std::time::Duration;

/// Top-level configuration. Either or both roles may be active: a site role
/// (newt: shares local resources) and a client role (olm: reaches private
/// resources). A role is active when its credentials are present.
#[derive(Debug, Clone)]
pub struct Config {
    pub log_level: String,
    pub site: Option<SiteRun>,
    pub client: Option<ClientRun>,
}

/// Site (newt) role: registers a site and proxies server-initiated connections
/// to local targets.
#[derive(Debug, Clone)]
pub struct SiteRun {
    pub endpoint: String,
    pub id: String,
    pub secret: String,
    pub mtu: usize,
    pub skip_tls_verify: bool,
    pub udp_idle_timeout: Duration,
}

/// How the client (olm) role exposes remote resources to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessMode {
    /// Kernel TUN interface plus OS routes: transparent routing of host/LAN
    /// traffic into remote subnets. Needs /dev/net/tun and CAP_NET_ADMIN.
    Kernel,
    /// Userspace netstack with local TCP forwards / SOCKS5: no privileges, runs
    /// anywhere, but not transparent (apps target the local listeners).
    Userspace,
}

/// A userspace forward: accept TCP on `listen_port` locally, dial
/// `dest_host:dest_port` through the tunnel.
#[derive(Debug, Clone)]
pub struct Forward {
    pub listen_port: u16,
    pub dest_host: String,
    pub dest_port: u16,
}

/// Client (olm) role.
#[derive(Debug, Clone)]
pub struct ClientRun {
    pub endpoint: String,
    pub id: String,
    pub secret: String,
    pub user_token: String,
    pub org_id: String,
    pub mtu: usize,
    pub skip_tls_verify: bool,
    pub access: AccessMode,
    pub interface: String,
    pub forwards: Vec<Forward>,
    pub socks_port: Option<u16>,
}

/// Mutable accumulator while reading env then CLI.
struct Raw {
    endpoint: String,
    mtu: usize,
    log_level: String,
    skip_tls_verify: bool,
    udp_idle_timeout: Duration,
    // site
    newt_id: String,
    newt_secret: String,
    // client
    olm_id: String,
    olm_secret: String,
    user_token: String,
    org_id: String,
    access: AccessMode,
    interface: String,
    forwards: Vec<Forward>,
    socks_port: Option<u16>,
}

impl Default for Raw {
    fn default() -> Self {
        Raw {
            endpoint: String::new(),
            mtu: 1280,
            log_level: "INFO".into(),
            skip_tls_verify: false,
            udp_idle_timeout: Duration::from_secs(90),
            newt_id: String::new(),
            newt_secret: String::new(),
            olm_id: String::new(),
            olm_secret: String::new(),
            user_token: String::new(),
            org_id: String::new(),
            access: default_access(),
            interface: "olm".into(),
            forwards: Vec::new(),
            socks_port: None,
        }
    }
}

fn default_access() -> AccessMode {
    if cfg!(target_os = "linux") { AccessMode::Kernel } else { AccessMode::Userspace }
}

impl Config {
    /// Build from (env_lookup, args). `env` maps NAME->value; `args` is the CLI
    /// flag list (without argv[0]). CLI overrides env. At least one role's
    /// credentials must be present.
    pub fn from_sources(
        env: &dyn Fn(&str) -> Option<String>,
        args: &[String],
    ) -> Result<Config, String> {
        let mut r = Raw::default();

        if let Some(v) = env("PANGOLIN_ENDPOINT") { r.endpoint = v; }
        if let Some(v) = env("MTU") { r.mtu = v.parse().map_err(|_| "bad MTU")?; }
        if let Some(v) = env("LOG_LEVEL") { r.log_level = v; }
        if let Some(v) = env("SKIP_TLS_VERIFY") { r.skip_tls_verify = truthy(&v); }
        if let Some(v) = env("NEWT_UDP_PROXY_IDLE_TIMEOUT") { r.udp_idle_timeout = parse_secs(&v)?; }

        if let Some(v) = env("NEWT_ID") { r.newt_id = v; }
        if let Some(v) = env("NEWT_SECRET") { r.newt_secret = v; }

        if let Some(v) = env("OLM_ID") { r.olm_id = v; }
        if let Some(v) = env("OLM_SECRET") { r.olm_secret = v; }
        if let Some(v) = env("OLM_USER_TOKEN") { r.user_token = v; }
        if let Some(v) = env("PANGOLIN_ORG_ID").or_else(|| env("ORG_ID")) { r.org_id = v; }
        if let Some(v) = env("OLM_ACCESS_MODE") { r.access = parse_access(&v)?; }
        if let Some(v) = env("OLM_INTERFACE") { r.interface = v; }
        if let Some(v) = env("OLM_FORWARDS") { r.forwards = parse_forwards(&v)?; }
        if let Some(v) = env("OLM_SOCKS_PORT") { r.socks_port = Some(v.parse().map_err(|_| "bad OLM_SOCKS_PORT")?); }

        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "-endpoint" | "--endpoint" => r.endpoint = next(&mut it, a)?,
                "-id" | "--id" => r.newt_id = next(&mut it, a)?,
                "-secret" | "--secret" => r.newt_secret = next(&mut it, a)?,
                "-mtu" | "--mtu" => r.mtu = next(&mut it, a)?.parse().map_err(|_| "bad --mtu")?,
                "-log-level" | "--log-level" => r.log_level = next(&mut it, a)?,
                "-skip-tls-verify" | "--skip-tls-verify" => r.skip_tls_verify = true,
                "-olm-id" | "--olm-id" => r.olm_id = next(&mut it, a)?,
                "-olm-secret" | "--olm-secret" => r.olm_secret = next(&mut it, a)?,
                "-olm-user-token" | "--olm-user-token" => r.user_token = next(&mut it, a)?,
                "-org-id" | "--org-id" => r.org_id = next(&mut it, a)?,
                "-olm-access" | "--olm-access" => r.access = parse_access(&next(&mut it, a)?)?,
                "-olm-interface" | "--olm-interface" => r.interface = next(&mut it, a)?,
                "-olm-forwards" | "--olm-forwards" => r.forwards = parse_forwards(&next(&mut it, a)?)?,
                "-olm-socks-port" | "--olm-socks-port" =>
                    r.socks_port = Some(next(&mut it, a)?.parse().map_err(|_| "bad --olm-socks-port")?),
                other => return Err(format!("unknown flag: {other}")),
            }
        }

        if r.endpoint.is_empty() {
            return Err("PANGOLIN_ENDPOINT (or --endpoint) is required".into());
        }

        let site = if !r.newt_id.is_empty() && !r.newt_secret.is_empty() {
            Some(SiteRun {
                endpoint: r.endpoint.clone(),
                id: r.newt_id.clone(),
                secret: r.newt_secret.clone(),
                mtu: r.mtu,
                skip_tls_verify: r.skip_tls_verify,
                udp_idle_timeout: r.udp_idle_timeout,
            })
        } else { None };

        let client = if !r.olm_id.is_empty() && !r.olm_secret.is_empty() {
            Some(ClientRun {
                endpoint: r.endpoint.clone(),
                id: r.olm_id.clone(),
                secret: r.olm_secret.clone(),
                user_token: r.user_token.clone(),
                org_id: r.org_id.clone(),
                mtu: r.mtu,
                skip_tls_verify: r.skip_tls_verify,
                access: r.access.clone(),
                interface: r.interface.clone(),
                forwards: r.forwards.clone(),
                socks_port: r.socks_port,
            })
        } else { None };

        if site.is_none() && client.is_none() {
            return Err("no role configured: set NEWT_ID/NEWT_SECRET (site) and/or OLM_ID/OLM_SECRET (client)".into());
        }

        Ok(Config { log_level: r.log_level, site, client })
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

fn parse_access(v: &str) -> Result<AccessMode, String> {
    match v.to_ascii_lowercase().as_str() {
        "kernel" | "tun" => Ok(AccessMode::Kernel),
        "userspace" | "user" | "socks" => Ok(AccessMode::Userspace),
        _ => Err(format!("bad access mode: {v} (kernel|userspace)")),
    }
}

/// Parse "listen:host:port,listen:host:port" into forwards.
fn parse_forwards(v: &str) -> Result<Vec<Forward>, String> {
    let mut out = Vec::new();
    for spec in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (listen, rest) = spec.split_once(':').ok_or_else(|| format!("bad forward: {spec}"))?;
        let (host, port) = rest.rsplit_once(':').ok_or_else(|| format!("bad forward: {spec}"))?;
        out.push(Forward {
            listen_port: listen.parse().map_err(|_| format!("bad listen port: {spec}"))?,
            dest_host: host.to_string(),
            dest_port: port.parse().map_err(|_| format!("bad dest port: {spec}"))?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_overrides_env_and_builds_site() {
        let env = |k: &str| match k {
            "PANGOLIN_ENDPOINT" => Some("https://env".into()),
            "NEWT_ID" => Some("envid".into()),
            "NEWT_SECRET" => Some("envsecret".into()),
            _ => None,
        };
        let args = vec!["--endpoint".into(), "https://cli".into()];
        let c = Config::from_sources(&env, &args).unwrap();
        let site = c.site.expect("site role");
        assert_eq!(site.endpoint, "https://cli");
        assert_eq!(site.id, "envid");
        assert!(c.client.is_none());
    }

    #[test]
    fn no_role_errors() {
        let env = |k: &str| match k {
            "PANGOLIN_ENDPOINT" => Some("https://x".into()),
            _ => None,
        };
        assert!(Config::from_sources(&env, &[]).is_err());
    }

    #[test]
    fn missing_endpoint_errors() {
        let env = |_: &str| None;
        assert!(Config::from_sources(&env, &[]).is_err());
    }

    #[test]
    fn both_roles_active() {
        let env = |k: &str| match k {
            "PANGOLIN_ENDPOINT" => Some("https://x".into()),
            "NEWT_ID" => Some("n".into()),
            "NEWT_SECRET" => Some("ns".into()),
            "OLM_ID" => Some("o".into()),
            "OLM_SECRET" => Some("os".into()),
            _ => None,
        };
        let c = Config::from_sources(&env, &[]).unwrap();
        assert!(c.site.is_some());
        let client = c.client.expect("client role");
        assert_eq!(client.id, "o");
    }

    #[test]
    fn parses_forwards_and_access() {
        let env = |k: &str| match k {
            "PANGOLIN_ENDPOINT" => Some("https://x".into()),
            "OLM_ID" => Some("o".into()),
            "OLM_SECRET" => Some("os".into()),
            "OLM_ACCESS_MODE" => Some("userspace".into()),
            "OLM_FORWARDS" => Some("8080:10.0.0.5:80, 9090:10.0.0.6:443".into()),
            _ => None,
        };
        let c = Config::from_sources(&env, &[]).unwrap();
        let client = c.client.unwrap();
        assert_eq!(client.access, AccessMode::Userspace);
        assert_eq!(client.forwards.len(), 2);
        assert_eq!(client.forwards[0].listen_port, 8080);
        assert_eq!(client.forwards[1].dest_host, "10.0.0.6");
        assert_eq!(client.forwards[1].dest_port, 443);
    }
}
