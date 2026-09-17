# Interop test vectors

Shared JSON fixtures that every CLASP implementation runs to prove conformance.
See [implementation design §7](../docs/implementation-design.md).

- `norm.json` — `(pw, uid) → Norm`
- `basalt.json` — `(Norm, salt_c, version) → A`
- `keys.json` — `A → pk`, and `(A, message) → sig`
- `oprf.json` — blind / eval / unblind round trips with fixed randomness
- `transcript.json` — full registration + login transcripts (baseline and OPRF)

Fixtures are generated from `clasp-core` and are language-agnostic.
