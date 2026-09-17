//! Ed25519 key derivation and signing (spec §3).
//!
//! `sk = A` (the 32-byte Basalt seed), `pk = A·G`. Signing is constant-time
//! via `ed25519-dalek`.

/// Derive the Ed25519 public key (the stored verifier) from the Basalt seed `A`.
///
/// TODO: `SigningKey::from_bytes(seed).verifying_key().to_bytes()`.
pub fn public_key(_seed: &[u8; 32]) -> [u8; 32] {
    todo!("derive verifying key from seed")
}

/// Sign a message with the seed-derived key.
///
/// `message = "AUTH" ‖ uid ‖ nonce [ ‖ tls_exporter ]` (spec §3.2, §6.2).
/// TODO: `SigningKey::from_bytes(seed).sign(message).to_bytes()`.
pub fn sign(_seed: &[u8; 32], _message: &[u8]) -> [u8; 64] {
    todo!("sign message with seed-derived key")
}
