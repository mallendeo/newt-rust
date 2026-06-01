use alloc::string::String;

/// A proxy target parsed from "listenPort:host:targetPort".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub listen_port: u16,
    pub host: String,
    pub target_port: u16,
}

impl Target {
    /// Parse "listenPort:host:targetPort". `host` may be a bracketed IPv6
    /// literal, e.g. "3001:[fd00::1]:443".
    pub fn parse(s: &str) -> Option<Target> {
        let (listen, rest) = s.split_once(':')?;
        let listen_port: u16 = listen.parse().ok()?;
        let (host, port) = if let Some(after) = rest.strip_prefix('[') {
            let close = after.find(']')?;
            let host = &after[..close];
            let port = after[close + 1..].strip_prefix(':')?;
            (host, port)
        } else {
            rest.rsplit_once(':')?
        };
        let target_port: u16 = port.parse().ok()?;
        Some(Target { listen_port, host: String::from(host), target_port })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn parses_ipv4() {
        let t = Target::parse("3001:192.168.1.1:80").unwrap();
        assert_eq!(t, Target { listen_port: 3001, host: "192.168.1.1".to_string(), target_port: 80 });
    }

    #[test]
    fn parses_bracketed_ipv6() {
        let t = Target::parse("3001:[::1]:8080").unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.listen_port, 3001);
        assert_eq!(t.target_port, 8080);
    }

    #[test]
    fn rejects_missing_parts() {
        assert!(Target::parse("3001:host").is_none());
        assert!(Target::parse("notaport:host:80").is_none());
    }
}
