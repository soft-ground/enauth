# enauth

Enhanced authentication method. `enauth` implements **CLASP** — *Client-side Load-shifted Authentication via Split Proof* — a password-authentication protocol that moves the heavy memory-hard hashing to the client and leaves the server only lightweight verification.

## Why

- **Server DoS resistance** — the server performs no memory-hard work; the only heavy computation is client-side.
- **Pass-the-Hash / replay resistance** — the value crossing the network is bound to a one-time nonce and cannot be reused.
- **Database-leak resistance** — the server stores only a public verifier (`pk`); offline cracking cost remains that of the memory-hard KDF.

## Components

- **CLASP** — the protocol: a challenge-response over a password-derived Ed25519 signing key, with an optional OPRF hardening profile.
- **Basalt** — the memory-hard KDF profile: Argon2id (RFC 9106) plus a fixed hardening wrapper. Not a new primitive.

## Repository layout

| Path | Contents |
|---|---|
| `docs/` | Protocol spec, KDF tuning, implementation design |
| `core/clasp-core/` | Rust crypto core (Basalt, key derivation, VOPRF) — no I/O |
| `core/clasp-wasm/` | `wasm-bindgen` wrapper exposing the core to JavaScript |
| `packages/client-js/` | Browser client SDK (TypeScript) |
| `packages/server-node/` | Reference server SDK (Node/TypeScript) |
| `vectors/` | Shared interop test vectors (JSON) |

## Documentation

- [CLASP Protocol Specification](docs/clasp-spec.md)
- [Basalt Parameter Tuning](docs/basalt-tuning.md)
- [Implementation Design](docs/implementation-design.md)

## Status

Early design and scaffolding. **Not production-ready — do not use for real authentication yet.**

## License

TBD (planned open source).
