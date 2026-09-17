//! wasm-bindgen wrapper exposing `clasp-core` to JavaScript.
//! See `docs/implementation-design.md` §3, §5.1.
//!
//! Security boundary: the password enters WASM and only *public* outputs
//! (the verifier `pk`, a signature `sig`, or a blinded OPRF element) leave it.
//! The Basalt seed `A` and the derived signing key never cross into JS.

use clasp_core::{basalt, keys, norm};
use wasm_bindgen::prelude::*;

fn resolve_params(version: &str) -> Result<basalt::Params, JsError> {
    basalt::params(version).ok_or_else(|| JsError::new("unknown Basalt version"))
}

/// Registration (baseline profile): derive the Ed25519 verifier `pk` from the
/// password. Returns 32 bytes. The seed `A` never leaves WASM.
#[wasm_bindgen]
pub fn derive_public_key(
    password: &[u8],
    uid: &[u8],
    salt_c: &[u8],
    version: &str,
) -> Result<Vec<u8>, JsError> {
    let params = resolve_params(version)?;
    let preimage = norm::norm(password, uid);
    let seed = basalt::basalt(&preimage[..], salt_c, &params);
    Ok(keys::public_key(&seed).to_vec())
}

/// Login (baseline profile): derive `A` and sign `message` in one call.
/// `message` = `"AUTH" ‖ uid ‖ nonce [ ‖ tls_exporter ]`, built by the caller.
/// Returns a 64-byte signature. The seed never leaves WASM.
#[wasm_bindgen]
pub fn derive_and_sign(
    password: &[u8],
    uid: &[u8],
    salt_c: &[u8],
    version: &str,
    message: &[u8],
) -> Result<Vec<u8>, JsError> {
    let params = resolve_params(version)?;
    let preimage = norm::norm(password, uid);
    let seed = basalt::basalt(&preimage[..], salt_c, &params);
    Ok(keys::sign(&seed, message).to_vec())
}

// TODO: CLASP-OPRF exports (oprf_blind + oprf_finalize variants) once the
// baseline WASM path is wired end-to-end through client-js.
