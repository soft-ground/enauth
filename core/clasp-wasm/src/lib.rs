//! wasm-bindgen wrapper exposing `clasp-core` to JavaScript.
//! See `docs/implementation-design.md` §3.

use wasm_bindgen::prelude::*;

/// Compute the Basalt seed `A` from a password and salt for a given version.
///
/// Runs `Norm` then `Basalt` inside WASM so the password never crosses into JS
/// as a derived credential. TODO: wire up once `clasp_core::basalt` is implemented.
#[wasm_bindgen]
pub fn basalt_seed(
    _password: &[u8],
    _uid: &[u8],
    _salt_c: &[u8],
    _version: &str,
) -> Result<Vec<u8>, JsError> {
    Err(JsError::new("not yet implemented"))
}
