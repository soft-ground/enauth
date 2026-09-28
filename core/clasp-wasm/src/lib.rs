//! wasm-bindgen wrapper exposing `clasp-core` to JavaScript.
//! See `docs/implementation-design.md` §3, §5.1.
//!
//! Security boundary: the password enters WASM and only *public* outputs
//! (the verifier `pk`, a signature `sig`, or a blinded OPRF element) leave it.
//! The Basalt seed `A`, the OPRF output `rw`, and the signing key never cross
//! into JS.

use clasp_core::{basalt, keys, norm, oprf};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

fn resolve_params(version: &str) -> Result<basalt::Params, JsError> {
    basalt::params(version).ok_or_else(|| JsError::new("unknown Basalt version"))
}

// ---------------------------------------------------------------------------
// Baseline profile
// ---------------------------------------------------------------------------

/// Registration (baseline): derive the Ed25519 verifier `pk` from the password.
/// Returns 32 bytes. The seed `A` never leaves WASM.
#[wasm_bindgen]
pub fn derive_public_key(
    password: &[u8],
    uid: &[u8],
    salt_c: &[u8],
    version: &str,
) -> Result<Vec<u8>, JsError> {
    let params = resolve_params(version)?;
    let preimage = norm::norm(password, uid);
    let seed = basalt::basalt(&preimage[..], salt_c, &params)
        .map_err(|e| JsError::new(&format!("basalt: {e}")))?;
    Ok(keys::public_key(&seed).to_vec())
}

/// Login (baseline): derive `A` and sign `message` in one call.
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
    let seed = basalt::basalt(&preimage[..], salt_c, &params)
        .map_err(|e| JsError::new(&format!("basalt: {e}")))?;
    Ok(keys::sign(&seed, message).to_vec())
}

// ---------------------------------------------------------------------------
// CLASP-OPRF profile
// ---------------------------------------------------------------------------

/// Output of [`oprf_blind`]: the opaque client state to persist and the blinded
/// element to send to the server.
#[wasm_bindgen]
pub struct OprfBlindResult {
    state: Vec<u8>,
    blinded: Vec<u8>,
}

#[wasm_bindgen]
impl OprfBlindResult {
    /// Serialized client state; pass back to the finalize functions.
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> Vec<u8> {
        self.state.clone()
    }

    /// Serialized blinded element; send to the server's `oprf/eval` endpoint.
    #[wasm_bindgen(getter)]
    pub fn blinded(&self) -> Vec<u8> {
        self.blinded.clone()
    }
}

/// Client (OPRF): blind the normalized preimage of `(password, uid)`.
#[wasm_bindgen]
pub fn oprf_blind(password: &[u8], uid: &[u8]) -> Result<OprfBlindResult, JsError> {
    let input = norm::norm(password, uid);
    let mut rng = OsRng;
    let blinded =
        oprf::blind(&input[..], &mut rng).map_err(|e| JsError::new(&format!("oprf blind: {e}")))?;
    Ok(OprfBlindResult {
        state: blinded.state,
        blinded: blinded.blinded_element,
    })
}

/// Server (OPRF): generate a fresh `k_oprf` (serialized scalar).
#[wasm_bindgen]
pub fn oprf_generate_key() -> Vec<u8> {
    let mut rng = OsRng;
    oprf::generate_key(&mut rng)
}

/// Server (OPRF): evaluate a blinded element under `k_oprf` (serialized scalar).
/// Exposed from the same crate as the client so the VOPRF encoding matches.
#[wasm_bindgen]
pub fn oprf_eval(key: &[u8], blinded_element: &[u8]) -> Result<Vec<u8>, JsError> {
    oprf::eval(key, blinded_element).map_err(|e| JsError::new(&format!("oprf eval: {e}")))
}

/// Client (OPRF): finalize the OPRF and derive the verifier `pk`.
/// `rw` and the seed stay in WASM.
#[wasm_bindgen]
pub fn oprf_derive_public_key(
    state: &[u8],
    password: &[u8],
    uid: &[u8],
    salt_c: &[u8],
    version: &str,
    evaluated: &[u8],
) -> Result<Vec<u8>, JsError> {
    let params = resolve_params(version)?;
    let input = norm::norm(password, uid);
    let rw = oprf::finalize(state, &input[..], evaluated)
        .map_err(|e| JsError::new(&format!("oprf finalize: {e}")))?;
    let seed = basalt::basalt(&rw, salt_c, &params)
        .map_err(|e| JsError::new(&format!("basalt: {e}")))?;
    Ok(keys::public_key(&seed).to_vec())
}

/// Client (OPRF): finalize the OPRF, derive `A`, and sign `message`.
/// `rw` and the seed stay in WASM.
#[wasm_bindgen]
pub fn oprf_derive_and_sign(
    state: &[u8],
    password: &[u8],
    uid: &[u8],
    salt_c: &[u8],
    version: &str,
    evaluated: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, JsError> {
    let params = resolve_params(version)?;
    let input = norm::norm(password, uid);
    let rw = oprf::finalize(state, &input[..], evaluated)
        .map_err(|e| JsError::new(&format!("oprf finalize: {e}")))?;
    let seed = basalt::basalt(&rw, salt_c, &params)
        .map_err(|e| JsError::new(&format!("basalt: {e}")))?;
    Ok(keys::sign(&seed, message).to_vec())
}
