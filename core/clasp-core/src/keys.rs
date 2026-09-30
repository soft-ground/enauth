//! Ed25519 key derivation and signing (spec §3).
//!
//! `sk = A` (the 32-byte Basalt seed), `pk = A·G`. Signing is constant-time
//! via `ed25519-dalek`.

use ed25519_dalek::{Signer, SigningKey};

/// Derive the Ed25519 public key (the stored verifier) from the Basalt seed `A`.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Sign a message with the seed-derived key.
///
/// `message = "AUTH" ‖ uid ‖ nonce [ ‖ tls_exporter ]` (spec §3.2, §6.2).
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use hex_literal::hex;

    #[test]
    fn public_key_is_deterministic() {
        let seed = [7u8; 32];
        assert_eq!(public_key(&seed), public_key(&seed));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let seed = [42u8; 32];
        let pk = VerifyingKey::from_bytes(&public_key(&seed)).unwrap();
        let msg = b"AUTH|alice|nonce";

        let sig = Signature::from_bytes(&sign(&seed, msg));
        assert!(pk.verify(msg, &sig).is_ok());
        assert!(pk.verify(b"tampered message", &sig).is_err());
    }

    /// RFC 8032 §7.1 TEST 1 (empty message) — known-answer test.
    #[test]
    fn rfc8032_test_vector_1() {
        let seed = hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_pk = hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_sig = hex!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );

        assert_eq!(public_key(&seed), expected_pk);
        assert_eq!(sign(&seed, b""), expected_sig);
    }
}
