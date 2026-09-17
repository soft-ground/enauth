//! VOPRF (RFC 9497, ristretto255) for the optional `CLASP-OPRF` profile (spec §3.3).
//!
//! Client `blind` / `finalize` run on the device; server `eval` applies `k_oprf`.
//! TODO: implement with the `voprf` crate.

/// Client: blind the preimage, returning `(blind, blinded_element)`.
pub fn blind(_preimage: &[u8]) -> (Vec<u8>, Vec<u8>) {
    todo!("VOPRF blind")
}

/// Server: evaluate the blinded element under key `k_oprf[v]`.
pub fn eval(_key: &[u8], _blinded_element: &[u8]) -> Vec<u8> {
    todo!("VOPRF evaluate")
}

/// Client: unblind and finalize into `rw`, the input to Basalt.
pub fn finalize(_blind: &[u8], _evaluated_element: &[u8]) -> Vec<u8> {
    todo!("VOPRF unblind + finalize")
}
