//! Basalt memory-hard KDF profile (spec §2, `docs/basalt-tuning.md`).
//!
//! Wraps Argon2id (RFC 9106) with version-pinned parameters. Not a new primitive.

use zeroize::Zeroizing;

/// Resolved Argon2id parameters for a Basalt version.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations (time cost).
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

/// Basalt-v1 (provisional; pending device measurement — see `docs/basalt-tuning.md`).
pub const V1: Params = Params { m_kib: 65536, t: 3, p: 1 };

/// Resolve parameters for a stored `basalt_version`.
pub fn params(version: &str) -> Option<Params> {
    match version {
        crate::BASALT_VERSION_V1 => Some(V1),
        _ => None,
    }
}

/// Compute `A = Basalt(preimage, salt_c)` as a 32-byte seed.
///
/// TODO: implement with the `argon2` crate (Argon2id, `outLen = 32`); zeroize scratch.
pub fn basalt(_preimage: &[u8], _salt_c: &[u8], _params: &Params) -> Zeroizing<[u8; 32]> {
    todo!("Argon2id via the `argon2` crate")
}
