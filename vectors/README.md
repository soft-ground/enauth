# Interop test vectors

Shared JSON fixtures that every CLASP implementation runs to prove conformance.
See [implementation design §7](../docs/implementation-design.md).

- `norm.json` — `Norm(pw, uid)`
- `basalt.json` — `Basalt(preimage, salt_c, params)` → `A`
- `keys.json` — `A` → `pk`, and `(A, message)` → `sig` (includes the RFC 8032 TEST 1 vector)
- `oprf.json` — `rw = OPRF(k_oprf, input)` (VOPRF ristretto255)
- `transcript.json` — full baseline and OPRF register/login derivations

All values are hex-encoded and each vector carries its own parameters, so ports
in any language reproduce them exactly. Argon2id parameters in the fixtures are
small for test speed; the production profile is Basalt-v1 (`m=65536, t=3, p=1`).

## Regenerate / verify

Generated from and re-verified against the reference implementation
(`core/clasp-core/tests/vectors.rs`):

```sh
# verify the committed fixtures match the reference implementation
cargo test -p clasp-core --test vectors

# regenerate the fixtures after an intentional change
CLASP_REGEN_VECTORS=1 cargo test -p clasp-core --test vectors
```
