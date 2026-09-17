//! VOPRF (RFC 9497, ristretto255) for the optional `CLASP-OPRF` profile (spec §3.3).
//!
//! Client `blind` / `finalize` run on the device; server `eval` applies `k_oprf`.
//! The API is byte-oriented because a server round-trip happens between `blind`
//! and `finalize`, so the client's blinding state must be serialized across the
//! boundary (spec §3.3, `docs/implementation-design.md` §4.1).

use rand_core::{CryptoRng, RngCore};
use voprf::{BlindedElement, EvaluationElement, OprfClient, OprfServer, Ristretto255};

type Cs = Ristretto255;

/// Result of a client blind: opaque state to persist locally, and the blinded
/// element to send to the server's `oprf_eval` endpoint.
pub struct Blinded {
    /// Serialized `OprfClient` state; pass back to [`finalize`].
    pub state: Vec<u8>,
    /// Serialized blinded element; send to the server.
    pub blinded_element: Vec<u8>,
}

/// Client: blind `input` (the normalized preimage).
pub fn blind<R: RngCore + CryptoRng>(input: &[u8], rng: &mut R) -> Result<Blinded, voprf::Error> {
    let result = OprfClient::<Cs>::blind(input, rng)?;
    Ok(Blinded {
        state: result.state.serialize().to_vec(),
        blinded_element: result.message.serialize().to_vec(),
    })
}

/// Server: generate a fresh `k_oprf` (serialized scalar) for a key version.
pub fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<u8> {
    OprfServer::<Cs>::new(rng)
        .expect("OPRF key generation")
        .serialize()
        .to_vec()
}

/// Server: evaluate a blinded element under the key `k_oprf[v]` (serialized scalar).
pub fn eval(key: &[u8], blinded_element: &[u8]) -> Result<Vec<u8>, voprf::Error> {
    let server = OprfServer::<Cs>::new_with_key(key)?;
    let element = BlindedElement::<Cs>::deserialize(blinded_element)?;
    Ok(server.blind_evaluate(&element).serialize().to_vec())
}

/// Server: compute the deterministic OPRF output `rw` for `input` directly
/// (unblinded). Equals what the client's blind → eval → finalize path yields;
/// useful for test vectors.
pub fn evaluate(key: &[u8], input: &[u8]) -> Result<Vec<u8>, voprf::Error> {
    let server = OprfServer::<Cs>::new_with_key(key)?;
    Ok(server.evaluate(input)?.to_vec())
}

/// Client: unblind and finalize into `rw`, the input to Basalt.
pub fn finalize(
    state: &[u8],
    input: &[u8],
    evaluated_element: &[u8],
) -> Result<Vec<u8>, voprf::Error> {
    let client = OprfClient::<Cs>::deserialize(state)?;
    let element = EvaluationElement::<Cs>::deserialize(evaluated_element)?;
    Ok(client.finalize(input, &element)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn blinded_roundtrip_matches_direct_evaluation() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let input = b"enauth normalized preimage";

        // A server with a fixed key; `key` is its serialized scalar.
        let server = OprfServer::<Cs>::new(&mut rng).unwrap();
        let key = server.serialize().to_vec();

        // Client blind -> server eval -> client finalize.
        let blinded = blind(input, &mut rng).unwrap();
        let evaluated = eval(&key, &blinded.blinded_element).unwrap();
        let rw = finalize(&blinded.state, input, &evaluated).unwrap();

        // The blinded path must equal the server's direct (unblinded) evaluation.
        let direct = server.evaluate(input).unwrap().to_vec();
        assert_eq!(rw, direct);
    }

    #[test]
    fn different_keys_give_different_outputs() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let input = b"pw";

        let server_a = OprfServer::<Cs>::new(&mut rng).unwrap();
        let server_b = OprfServer::<Cs>::new(&mut rng).unwrap();

        let a = server_a.evaluate(input).unwrap().to_vec();
        let b = server_b.evaluate(input).unwrap().to_vec();
        assert_ne!(a, b);
    }
}
