use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// Build a gerbil hole-punch datagram: an ephemeral-X25519 + ChaCha20-Poly1305
/// sealed `{<id_field>, token, publicKey}`, wrapped in the envelope the exit node
/// expects. The exit node uses this to track the connector's live UDP endpoint;
/// the WireGuard tunnel alone is not enough for it to keep reporting the peer.
/// `id_field` is "newtId" for a site or "olmId" for a client; `id` is the
/// matching newtId/olmId value.
pub fn build(id_field: &str, id: &str, token: &str, pub_b64: &str, server_pub_b64: &str) -> Option<Vec<u8>> {
    let raw: [u8; 32] = STANDARD.decode(server_pub_b64.trim()).ok()?.try_into().ok()?;
    let server_pub = PublicKey::from(raw);

    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&server_pub);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let plaintext = serde_json::json!({
        id_field: id,
        "token": token,
        "publicKey": pub_b64,
    })
    .to_string();
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes()).ok()?;

    let envelope = serde_json::json!({
        "ephemeralPublicKey": STANDARD.encode(eph_pub.as_bytes()),
        "nonce": STANDARD.encode(nonce),
        "ciphertext": STANDARD.encode(ciphertext),
    });
    Some(envelope.to_string().into_bytes())
}
