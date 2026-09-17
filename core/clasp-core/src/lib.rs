//! CLASP crypto core.
//!
//! Pure computation — no network or storage. Compiled to WASM for the browser
//! and to native targets via FFI. See `docs/implementation-design.md` §3.
//!
//! Security-critical requirements (spec §4):
//! - Constant-time comparisons via `subtle`; no secret-dependent branches.
//! - Zeroize all secret material (`Norm` output, `rw`, `A`, `sk`) after use.

pub mod basalt;
pub mod keys;
pub mod norm;
pub mod oprf;

/// Current Basalt profile version tag.
pub const BASALT_VERSION_V1: &str = "basalt-v1";
