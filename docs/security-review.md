# Internal security review

> **This is an internal engineering review, NOT an independent third-party
> security audit.** It was performed by the same party that wrote the code, so
> it carries the inherent blind spots of self-review. It does not include
> side-channel measurement, formal verification, or adversarial cryptographic
> analysis. Do not represent enauth as "audited". An independent professional
> audit is still required before any production use.

- Date: 2026-09-28
- Scope: whole codebase at commit `e8f6ebc` (core, wasm, client-js, server-node)
- Reviewer: internal (self-review)

## Methodology

- **Automated:** `pnpm audit` (npm advisories), `cargo audit` (RustSec), plus
  the existing dependency/license audit ([dependencies.md](dependencies.md)).
- **Manual:** code and protocol review against the CLASP threat model
  ([spec §5](clasp-spec.md)) — replay/nonce handling, DB-leak resistance, user
  enumeration, DoS surfaces, crypto API usage, secret handling, encoding.

## Automated scan results

| Scan | Result |
|---|---|
| `pnpm audit` | No known vulnerabilities |
| `cargo audit` | No known vulnerabilities (76 crates scanned, RustSec advisory DB) |

## Findings

Severity reflects impact **in this reference codebase**; several items are in
adapters explicitly documented as development-only.

| ID | Severity | Area | Summary |
|---|---|---|---|
| M1 | Medium | server-node (ref adapter) | Nonce store grows unboundedly (no expiry sweep) → memory DoS |
| M2 | Medium | server-node (http adapter) | Request body is buffered with no size limit → memory DoS |
| L1 | Low | core / wasm | OPRF output `rw` (password-derived secret) is not zeroized |
| L2 | Low | server + client | Timing side channels (user-existence oracle; length via pre-hash) |
| L3 | Low | server-node (ref) | No rate limiting by default → enumeration / probing / nonce spam |
| L4 | Low | core / wasm | `basalt` panics on malformed server-supplied salt/params (client DoS) |
| L5 | Low | server-node | `serverSecret` reused across HMAC purposes without subkey separation |
| I1 | Info | protocol | Registration is unauthenticated → account squatting (app-layer concern) |
| I2 | Info | server-node | `reg_token` is a bearer token until expiry (creation bounded to once) |
| I3 | Info | protocol | OPRF `phase`/version are client-asserted (lying only self-DoS) |
| I4 | Info | server-node | Session token is a non-verifiable placeholder |

### M1 — Nonce store memory exhaustion

`InMemoryNonceStore` ([adapters.ts](../packages/server-node/src/adapters.ts))
removes a nonce only on `consume`. Nonces issued by `login/init` but never
verified are never swept; `login/init` also issues a nonce for **non-existent**
uids (anti-enumeration), so an attacker can grow the map without bound by
spamming `login/init`. **Recommend:** periodic sweep or bounded LRU; in
production rely on a store with native TTL eviction (Redis `SET … EX`).

### M2 — Unbounded request body

`readJson` ([http.ts](../packages/server-node/src/http.ts)) concatenates all
request chunks with no cap. A large body exhausts memory. **Recommend:** enforce
a small maximum body size and reject oversized requests early.

### L1 — OPRF `rw` not zeroized

`oprf::finalize` ([oprf.rs](../core/clasp-core/src/oprf.rs)) returns `Vec<u8>`,
and the WASM OPRF derive paths hold `rw` as a plain `Vec<u8>`. `rw` is
password-derived and sensitive; the baseline path zeroizes its intermediates
(`Zeroizing`), so this is an inconsistency. **Recommend:** wrap `rw` in
`Zeroizing` (or zeroize after feeding it to Basalt).

### L2 — Timing side channels

- `login/init` takes different paths for known vs. unknown uid (record read vs.
  `pseudoSalt` HMAC), and `login/verify` runs the Ed25519 verify **only** for
  existing users — both are user-existence timing oracles.
- The client's `Norm` uses HKDF/HMAC over the raw password, whose runtime is
  block-granular in the password length. Basalt is length-independent (fixed
  32-byte preimage), but this fast pre-hash still carries a residual length
  signal — a nuance vs. the spec's "removes length timing" claim.

**Recommend:** equalize server paths (always do the pseudo-work; dummy-verify
for unknown users). The client pre-hash signal is minor and hard to exploit in a
browser; document it rather than claim full elimination.

### L3 — No rate limiting by default

`NoopRateLimiter` is the reference limiter, so `register/init`, `login/init`,
`login/verify`, and `oprf/eval` are unthrottled. This enables enumeration,
OPRF probing, and nonce-store spam (see M1). Documented as requiring a real
limiter; **recommend** shipping a token-bucket implementation and wiring it at
the HTTP edge as well.

### L4 — Client panic on malformed server input

`basalt::basalt` ([basalt.rs](../core/clasp-core/src/basalt.rs)) uses `.expect`
on `hash_password_into`, which panics if the server sends a salt shorter than
Argon2's 8-byte minimum. A malicious/buggy server can crash the client WASM.
**Recommend:** return a `Result` and validate `salt_c` length at the boundary
(already noted as a TODO in the code).

### L5 — `serverSecret` reuse

The same `serverSecret` keys the `reg_token` HMAC, the anti-enumeration
`pseudoSalt`, and the session token. No cross-protocol confusion is currently
exploitable (only `reg_token` is verified server-side), but **recommend**
deriving distinct subkeys via HKDF with per-purpose labels (defense in depth).

### I1–I4 (informational)

- **I1:** Anyone can `register/init` an unclaimed uid; binding an account to a
  real identity (email/phone verification) is the application's responsibility.
- **I2:** `reg_token` is a 5-minute bearer token; `createUser` bounds it to a
  single successful account creation. Consider making it single-use.
- **I3:** A client can lie about the OPRF `phase`/version, but this only breaks
  its own derivation — no cross-user impact.
- **I4:** The `login/verify` session token is a minimal placeholder, not a real
  verifiable session; deployments must supply their own session management.

## Remediation (2026-09-28)

Fixed in the same session; all tests remain green (core 13, server 7, integration 2):

- **M1** — `InMemoryNonceStore` now sweeps expired entries and hard-caps size (evict-oldest) to bound memory.
- **M2** — the HTTP adapter caps request bodies at 64 KiB and returns `413`.
- **L1** — `oprf::finalize` now returns `Zeroizing<Vec<u8>>`, so `rw` is wiped on drop.
- **L4** — `basalt` returns `Result` instead of panicking on a short/invalid salt; a regression test covers it.
- **L5** — the server derives per-purpose subkeys from `serverSecret` via HKDF-SHA256 (reg-token / pseudo-salt / session).
- **L2** — server paths equalized: `login/init` always computes the pseudo-salt, and `login/verify` runs an Ed25519 verify against a dummy key for unknown users. (The client-side pre-hash length signal is documented, not eliminated.)

Deferred by design: **L3** (a real rate limiter is deployment infrastructure — the interface and requirement are in place) and **I1–I4** (informational / application-layer or documented placeholders).

## Checked and found sound

- No password, seed `A`, signing key, or `rw` crosses the wire — only `pk`,
  `sig`, and (OPRF) a blinded element.
- Nonce single-use + uid-binding + TTL are enforced; replay is defeated.
- `reg_token` HMAC is compared in constant time (`timingSafeEqual`).
- `login/verify` returns a uniform `401` across all failure causes.
- Anti-enumeration structure is present (pseudo-salt, uniform `login/init`).
- Ed25519 verification is wrapped against exceptions on malformed inputs.
- Baseline derivation zeroizes `Norm`/`Basalt` intermediates.
- The signed message is length-prefixed and domain-separated (no concatenation
  ambiguity); client and server build it identically (interop vector confirms).
- Primitives are vetted crates (Argon2id, Ed25519, VOPRF); keys are
  cross-checked against the RFC 8032 known-answer vector.

## Limitations of this review

Self-review (not independent); no side-channel measurement; no formal
verification; no adversarial cryptographic analysis; no real-browser runtime
testing. Findings here reduce risk but do not substitute for an independent
professional audit.
