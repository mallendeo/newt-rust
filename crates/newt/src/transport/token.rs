use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use rustls::pki_types::ServerName;

/// POST `body` to <endpoint>/api/v1/auth/<kind>/get-token and return the JWT.
/// `kind` selects the credential type: "newt" for a site, "olm" for a client.
/// `body` carries the matching id field (newtId/olmId) plus secret and any
/// extra fields (userToken, orgId).
pub async fn get_token(
    endpoint: &str,
    kind: &str,
    body: &serde_json::Value,
    tls: Arc<rustls::ClientConfig>,
) -> std::io::Result<String> {
    let data = get_token_data(endpoint, kind, body, tls).await?;
    data["token"].as_str().map(|s| s.to_string())
        .ok_or_else(|| std::io::Error::other("no token in response"))
}

/// Like `get_token`, but returns the whole `data` object so callers (the client
/// role) can also read `exitNodes` alongside the token.
pub async fn get_token_data(
    endpoint: &str,
    kind: &str,
    body: &serde_json::Value,
    tls: Arc<rustls::ClientConfig>,
) -> std::io::Result<serde_json::Value> {
    let (scheme, hostport, host, port) = split_endpoint(endpoint)?;
    let body = body.to_string();
    // Pangolin rejects non-GET API calls without this fixed CSRF header.
    let req = format!(
        "POST /api/v1/auth/{kind}/get-token HTTP/1.1\r\nHost: {hostport}\r\n\
         Content-Type: application/json\r\nX-CSRF-Token: x-csrf-protection\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let raw = if scheme == "https" {
        let connector = TlsConnector::from(tls);
        let dns = ServerName::try_from(host.clone())
            .map_err(|_| std::io::Error::other("bad server name"))?;
        let mut s = connector.connect(dns, tcp).await?;
        s.write_all(req.as_bytes()).await?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await?;
        buf
    } else {
        let mut s = tcp;
        s.write_all(req.as_bytes()).await?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await?;
        buf
    };

    let text = String::from_utf8_lossy(&raw);
    let json_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let v: serde_json::Value = serde_json::from_str(text[json_start..].trim())
        .map_err(|e| std::io::Error::other(format!("token json: {e}")))?;
    Ok(v["data"].clone())
}

/// Returns (scheme, host:port, host, port). Accepts http(s):// and bare host.
pub fn split_endpoint(endpoint: &str) -> std::io::Result<(String, String, String, u16)> {
    let (scheme, rest) = match endpoint.split_once("://") {
        Some(("https", r)) => ("https", r),
        Some(("http", r)) => ("http", r),
        Some(_) => return Err(std::io::Error::other("unsupported scheme")),
        None => ("https", endpoint),
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.parse::<u16>().is_ok() => (h.to_string(), p.parse().unwrap()),
        _ => (rest.to_string(), if scheme == "https" { 443 } else { 80 }),
    };
    Ok((scheme.into(), format!("{host}:{port}"), host, port))
}

#[cfg(test)]
mod tests {
    use super::split_endpoint;
    #[test]
    fn splits_endpoints() {
        let (s, hp, h, p) = split_endpoint("https://app.example.com").unwrap();
        assert_eq!((s.as_str(), hp.as_str(), h.as_str(), p), ("https", "app.example.com:443", "app.example.com", 443));
        let (_, _, h, p) = split_endpoint("http://1.2.3.4:8080").unwrap();
        assert_eq!((h.as_str(), p), ("1.2.3.4", 8080));
    }
}
