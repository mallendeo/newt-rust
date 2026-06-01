use std::sync::Arc;
use rustls::ClientConfig;

/// Build a rustls ClientConfig using the ring provider and bundled webpki roots.
/// When `skip_verify` is set, server certificates are accepted unconditionally.
pub fn client_config(skip_verify: bool) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports default protocol versions");

    let cfg = if skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(noverify::NoVerify(provider)))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Arc::new(cfg)
}

mod noverify {
    use std::sync::Arc;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoVerify(pub Arc<CryptoProvider>);

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>],
            _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>,
            _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>,
            _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}
