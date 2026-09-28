# enauth documentation

- [CLASP Protocol Specification](clasp-spec.md) — the protocol (registration, login, OPRF, security analysis)
- [Basalt Parameter Tuning](basalt-tuning.md) — the memory-hard KDF profile and its parameters
- [Implementation Design](implementation-design.md) — reference-implementation architecture, API contract, SDK surfaces
- [Dependency & License Audit](dependencies.md) — third-party licenses and version pinning
- [Internal Security Review](security-review.md) — self-review findings + remediation (not an independent audit)

## Reference implementation

- `core/clasp-core` — Rust crypto core (Norm, Basalt, keys, OPRF)
- `core/clasp-wasm` — WASM bindings (browser + Node)
- `packages/client-js` — browser client SDK
- `packages/server-node` — reference server SDK
- [`vectors/`](../vectors/) — language-neutral interop test vectors
