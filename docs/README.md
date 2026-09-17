# enauth documentation

- [CLASP Protocol Specification](clasp-spec.md) — the protocol (registration, login, OPRF, security analysis)
- [Basalt Parameter Tuning](basalt-tuning.md) — the memory-hard KDF profile and its parameters
- [Implementation Design](implementation-design.md) — reference-implementation architecture, API contract, SDK surfaces

## Reference implementation

- `core/clasp-core` — Rust crypto core (Norm, Basalt, keys, OPRF)
- `core/clasp-wasm` — WASM bindings (browser + Node)
- `packages/client-js` — browser client SDK
- `packages/server-node` — reference server SDK
- [`vectors/`](../vectors/) — language-neutral interop test vectors
