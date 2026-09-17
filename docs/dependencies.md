# Dependency & license audit

Audited 2026-09-17. **Result: all dependencies (runtime and dev) use permissive
licenses compatible with distributing enauth under `MIT OR Apache-2.0`. No
copyleft (GPL/AGPL/MPL/…) and no unlicensed dependencies were found.**

Exact versions are pinned by the committed lockfiles (`Cargo.lock`,
`pnpm-lock.yaml`); the manifests keep semver ranges for flexibility.

## Rust (76 crates in the tree)

License distribution: `MIT OR Apache-2.0` (majority), `Apache-2.0 OR MIT`,
`MIT`, `BSD-3-Clause`, `BSD-2-Clause OR Apache-2.0 OR MIT`, `Unlicense OR MIT`,
and `(MIT OR Apache-2.0) AND Unicode-3.0` — all permissive.

Key cryptographic dependencies:

| Crate | Version | License |
|---|---|---|
| argon2 | 0.5.3 | MIT OR Apache-2.0 |
| ed25519-dalek | 2.2.0 | BSD-3-Clause |
| curve25519-dalek | 4.1.3 | BSD-3-Clause |
| voprf | 0.5.0 | MIT |
| hkdf | 0.12.4 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| subtle | 2.6.1 | BSD-3-Clause |
| zeroize | 1.9.0 | Apache-2.0 OR MIT |
| rand_core | 0.6.4 | MIT OR Apache-2.0 |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| wasm-bindgen | 0.2.128 | MIT OR Apache-2.0 |

## JavaScript

| Package | License | Scope |
|---|---|---|
| @noble/curves | MIT | runtime (server-node) |
| @noble/hashes | MIT | transitive |
| typescript | Apache-2.0 | dev |
| @types/node | MIT | dev |
| undici-types | MIT | dev |

## Attribution note

`BSD-3-Clause` (curve25519-dalek, ed25519-dalek, subtle) and `Unicode-3.0`
require retaining their copyright notices and disclaimers. When distributing
**binaries** — notably the compiled WASM bundle, which statically links these —
ship a `THIRD-PARTY-NOTICES` file bundling the upstream license texts.
(Not required for source distribution.)

## Reproduce this audit

```sh
# Rust: license of every crate in the tree
cargo metadata --format-version 1 | jq -r '.packages[] | "\(.name) \(.version) \(.license)"'

# JavaScript
pnpm licenses list
```
