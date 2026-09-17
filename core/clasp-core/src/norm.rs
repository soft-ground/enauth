//! Fixed-length preimage normalization (spec §2.1).
//!
//! `Norm(pw, uid) = HKDF-SHA512(ikm = pw, salt = uid, info = "enauth/basalt/v1")[:32]`
//!
//! Produces a constant 32-byte input regardless of password length, removing the
//! length-based timing channel and providing domain separation.

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

const INFO: &[u8] = b"enauth/basalt/v1";

/// Derive the fixed-length preimage. The returned buffer is zeroized on drop.
pub fn norm(pw: &[u8], uid: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha512>::new(Some(uid), pw);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(INFO, out.as_mut())
        .expect("32 is a valid HKDF-SHA512 output length");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_is_deterministic_and_32_bytes() {
        let a = norm(b"correct horse", b"alice");
        let b = norm(b"correct horse", b"alice");
        assert_eq!(a.as_ref(), b.as_ref());
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn norm_differs_by_uid() {
        let a = norm(b"pw", b"alice");
        let b = norm(b"pw", b"bob");
        assert_ne!(a.as_ref(), b.as_ref());
    }
}
