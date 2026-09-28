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
| `test/` | Cross-package HTTP integration test |

## Documentation

- [CLASP Protocol Specification](docs/clasp-spec.md)
- [Basalt Parameter Tuning](docs/basalt-tuning.md)
- [Implementation Design](docs/implementation-design.md)
- [Dependency & License Audit](docs/dependencies.md)
- [Internal Security Review](docs/security-review.md)

## Status

Reference implementation — complete for both the baseline and OPRF profiles and
verified end-to-end (Rust core, WASM bindings, browser client SDK, Node server
SDK, interop vectors, and an HTTP integration test). It has undergone an
**internal** security review but **no independent audit**, so it is **not
production-ready — do not use it to protect real accounts yet.**

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

> This project reuses the Argon2id memory-hard function (RFC 9106, reference
> implementation dual-licensed CC0-1.0 / Apache-2.0). Third-party dependency
> licenses are reviewed in [docs/dependencies.md](docs/dependencies.md).
