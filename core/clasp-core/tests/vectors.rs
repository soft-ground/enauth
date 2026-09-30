//! Interop test vectors: generated from the reference implementation and
//! re-verified against the committed JSON in `vectors/`.
//!
//! - Normal run (`cargo test`) recomputes every value and asserts it matches
//!   the committed `vectors/*.json`, guarding against regressions.
//! - Set `CLASP_REGEN_VECTORS=1` to (re)write the JSON files instead.
//!
//! Argon2id parameters here are intentionally small so the suite stays fast;
//! the production profile is Basalt-v1 (m=65536 KiB, t=3, p=1). Each vector
//! carries its own parameters, so other implementations reproduce them exactly.

use std::path::PathBuf;

use clasp_core::{basalt, keys, norm, oprf};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};

fn hx(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hx32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

/// Canonical CLASP login message (mirrors client-js / server-node):
/// `"CLASP-AUTH-v1" ‖ u32be(len(uid)) ‖ uid ‖ nonce`.
fn build_auth_message(uid: &str, nonce: &[u8]) -> Vec<u8> {
    let mut m = b"CLASP-AUTH-v1".to_vec();
    m.extend_from_slice(&(uid.len() as u32).to_be_bytes());
    m.extend_from_slice(uid.as_bytes());
    m.extend_from_slice(nonce);
    m
}

fn check_or_write(name: &str, value: Value) {
    let path = vectors_dir().join(name);
    if std::env::var("CLASP_REGEN_VECTORS").is_ok() {
        let mut out = serde_json::to_string_pretty(&value).unwrap();
        out.push('\n');
        std::fs::write(&path, out).unwrap();
    } else {
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing {name}; regenerate with CLASP_REGEN_VECTORS=1"));
        let existing: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            existing, value,
            "{name} out of date; regenerate with CLASP_REGEN_VECTORS=1"
        );
    }
}

fn norm_vectors() -> Value {
    let cases: Vec<Value> = [
        ("correct horse battery staple", "alice@example.com"),
        ("", "bob"),
        ("p@ssw0rd\u{1f510}", "user-123"),
    ]
    .iter()
    .map(|(pw, uid)| {
        let n = norm::norm(pw.as_bytes(), uid.as_bytes());
        json!({ "pw_utf8": pw, "uid_utf8": uid, "norm_hex": hx(&n[..]) })
    })
    .collect();
    json!({
        "description": "Norm(pw,uid) = HKDF-SHA512(ikm=pw, salt=uid, info=\"enauth/basalt/v1\")[:32]; pw/uid are UTF-8",
        "cases": cases,
    })
}

fn basalt_vectors() -> Value {
    let p = basalt::Params {
        m_kib: 32,
        t: 1,
        p: 1,
    };
    let preimage = b"basalt-preimage-0123456789";
    let salt_c = b"0123456789abcdef";
    let a = basalt::basalt(preimage, salt_c, &p).unwrap();
    json!({
        "description": "A = Argon2id(v1.3, m_kib, t, p, out=32). Production profile Basalt-v1 = {m_kib:65536,t:3,p:1}.",
        "cases": [{
            "preimage_hex": hx(preimage),
            "salt_c_hex": hx(salt_c),
            "m_kib": 32, "t": 1, "p": 1,
            "a_hex": hx(&a[..]),
        }],
    })
}

fn keys_vectors() -> Value {
    let seed1 = [0x11u8; 32];
    let msg1 = b"CLASP interop message";
    // RFC 8032 section 7.1 TEST 1 seed, empty message.
    let seed2 = hx32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    json!({
        "description": "pk = Ed25519 public key from seed A; sig = Ed25519(seed, message)",
        "cases": [
            {
                "seed_hex": hx(&seed1),
                "message_hex": hx(msg1),
                "pk_hex": hx(&keys::public_key(&seed1)),
                "sig_hex": hx(&keys::sign(&seed1, msg1)),
            },
            {
                "note": "RFC 8032 TEST 1 seed, empty message",
                "seed_hex": hx(&seed2),
                "message_hex": "",
                "pk_hex": hx(&keys::public_key(&seed2)),
                "sig_hex": hx(&keys::sign(&seed2, b"")),
            },
        ],
    })
}

fn oprf_vectors() -> Value {
    // Deterministic key from a fixed RNG seed so the vector is reproducible.
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let key = oprf::generate_key(&mut rng);
    let input = b"oprf-input-bytes";
    let rw = oprf::evaluate(&key, input).unwrap();
    json!({
        "description": "rw = OPRF(k_oprf, input), VOPRF over ristretto255 (RFC 9497). Deterministic output the blind->eval->finalize path unblinds to.",
        "cases": [{
            "key_hex": hx(&key),
            "input_hex": hx(input),
            "rw_hex": hx(&rw),
        }],
    })
}

fn transcript_vectors() -> Value {
    let pw = "hunter2";
    let uid = "erin@example.com";
    let salt_c = [0x22u8; 16];
    let nonce = [0x33u8; 32];
    let p = basalt::Params {
        m_kib: 32,
        t: 1,
        p: 1,
    };
    let message = build_auth_message(uid, &nonce);

    // Baseline: A = Basalt(Norm(pw,uid), salt_c)
    let n = norm::norm(pw.as_bytes(), uid.as_bytes());
    let seed = basalt::basalt(&n[..], &salt_c, &p).unwrap();
    let baseline = json!({
        "pw_utf8": pw, "uid_utf8": uid,
        "salt_c_hex": hx(&salt_c), "m_kib": 32, "t": 1, "p": 1,
        "nonce_hex": hx(&nonce),
        "pk_hex": hx(&keys::public_key(&seed)),
        "auth_message_hex": hx(&message),
        "sig_hex": hx(&keys::sign(&seed, &message)),
    });

    // OPRF: rw = OPRF(k_oprf, Norm(pw,uid)); A = Basalt(rw, salt_c)
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let key = oprf::generate_key(&mut rng);
    let rw = oprf::evaluate(&key, &n[..]).unwrap();
    let seed_o = basalt::basalt(&rw, &salt_c, &p).unwrap();
    let oprf_case = json!({
        "pw_utf8": pw, "uid_utf8": uid,
        "salt_c_hex": hx(&salt_c), "m_kib": 32, "t": 1, "p": 1,
        "k_oprf_hex": hx(&key),
        "rw_hex": hx(&rw),
        "nonce_hex": hx(&nonce),
        "pk_hex": hx(&keys::public_key(&seed_o)),
        "auth_message_hex": hx(&message),
        "sig_hex": hx(&keys::sign(&seed_o, &message)),
    });

    json!({
        "description": "Full register+login derivations. auth_message = CLASP-AUTH-v1 | u32be(len uid) | uid | nonce",
        "baseline": baseline,
        "oprf": oprf_case,
    })
}

#[test]
fn interop_vectors() {
    check_or_write("norm.json", norm_vectors());
    check_or_write("basalt.json", basalt_vectors());
    check_or_write("keys.json", keys_vectors());
    check_or_write("oprf.json", oprf_vectors());
    check_or_write("transcript.json", transcript_vectors());
}
