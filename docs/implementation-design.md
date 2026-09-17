# CLASP Implementation Design

Reference-implementation architecture for [CLASP](clasp-spec.md) / [Basalt](basalt-tuning.md).

| | |
|---|---|
| Status | Draft |
| Version | 0.1 |
| Date | 2026-09-17 |
| Author | soft-ground |

---

## 1. Stack decisions

| Layer | Choice | Rationale |
|---|---|---|
| Crypto core | **Rust**, compiled to **WASM + native** | One vetted core reused in browser (WASM), native mobile (FFI), and server. Strong constant-time crypto ecosystem: `argon2`, `ed25519-dalek`, `curve25519-dalek`/`voprf`, `subtle`, `zeroize`. |
| Reference server | **Node / TypeScript** | Matches the web-developer audience; lowest adoption barrier. Crypto delegated to the core (native binding or WASM). |
| Initial client | **Web first** | Browser WASM client SDK; native mobile deferred. Keeps initial scope tight. |

These are reference implementations. The wire protocol (§4) is language-agnostic so other stacks can interoperate via the shared test vectors (§7).

---

## 2. Repository layout (monorepo)

```
enauth/
├─ docs/
│  ├─ clasp-spec.md            # protocol specification
│  ├─ basalt-tuning.md         # KDF parameter tuning
│  └─ implementation-design.md # this document
├─ core/                       # Rust workspace
│  ├─ clasp-core/              # reusable crypto core (no I/O)
│  │  └─ src/{norm,basalt,keys,oprf,lib}.rs
│  └─ clasp-wasm/              # wasm-bindgen wrapper → npm package
├─ packages/
│  ├─ client-js/               # TS browser client SDK (wraps clasp-wasm)
│  └─ server-node/             # TS reference server SDK
├─ vectors/                    # shared interop test vectors (JSON)
├─ Cargo.toml                  # Rust workspace root
├─ package.json                # pnpm workspace root
└─ pnpm-workspace.yaml
```

Build/toolchain: Rust workspace via `cargo`; `wasm-pack` for the web build; `pnpm` workspace for JS packages. CI builds the WASM artifact and runs the §7 vectors against both `client-js` and `server-node`.

---

## 3. Crypto core (`clasp-core`)

Pure computation, no network or storage. Exposed to the web via `wasm-bindgen` and to native targets via C FFI / UniFFI.

| Module | Responsibility |
|---|---|
| `norm` | `Norm(pw, uid) = HKDF-SHA512(ikm=pw, salt=uid, info="enauth/basalt/v1")[:32]` |
| `basalt` | Argon2id wrapper; parameters resolved from `basalt_version` (see [tuning](basalt-tuning.md)) |
| `keys` | Ed25519 seed → key pair (`sk = A`, `pk = A·G`); constant-time `Sign` |
| `oprf` | RFC 9497 VOPRF over ristretto255 — client `blind`/`unblind`/`finalize`, server `eval` |

**Security-critical requirements:**
- Constant-time equality via `subtle`; no secret-dependent branches or early returns.
- `zeroize` all secret material (`Norm` output, `rw`, `A`, `sk`) after use.
- WASM built with a fixed linear-memory size sufficient for `M` (64 MiB v1) to avoid data-dependent allocation.
- The core never logs, and never receives `uid`/`pw` on any path that persists them.

---

## 4. Wire protocol (API contract)

All endpoints are `POST`, JSON bodies, versioned under `/clasp/v1/`. Binary fields are base64url. `oprf_key_version = "none"` disables the OPRF steps (baseline deployment).

### 4.1 Registration

```
POST /clasp/v1/register/init
  req:  { uid }
  res:  { salt_c, basalt_version, oprf_key_version, reg_token }
        // salt_c freshly generated; reg_token is a short-lived signed token
        // binding this init to its finalize. Rejected if uid already exists.

POST /clasp/v1/oprf/eval            // only when oprf_key_version != "none"
  req:  { uid, blinded_element, phase: "register" | "login" }
  res:  { evaluated_element, oprf_key_version }
        // server computes R = k_oprf[v]·B

POST /clasp/v1/register/finalize
  req:  { reg_token, pk }
  res:  { status: "ok" }
        // verifies reg_token, stores (uid, salt_c, basalt_version, oprf_key_version, pk)
```

### 4.2 Login

```
POST /clasp/v1/login/init
  req:  { uid }
  res:  { salt_c, basalt_version, oprf_key_version, nonce }
        // For an UNKNOWN uid, return a deterministic pseudo salt_c =
        // HMAC(server_secret, uid), default versions, and a real nonce,
        // with uniform timing — see §6 anti-enumeration.

POST /clasp/v1/login/verify
  req:  { uid, nonce, sig }
  res:  { session, ... }  |  401
        // atomically consume(nonce, uid); Verify(pk, "AUTH"‖uid‖nonce[‖tls_exporter], sig)
```

### 4.3 Re-enrollment (authenticated)

```
POST /clasp/v1/reenroll                       // requires an authenticated session
  req:  { new_pk, basalt_version, oprf_key_version }
  res:  { status: "ok" }
        // upgrade path for Basalt-v2 / OPRF enable/rotate (spec §7)
```

---

## 5. SDK surfaces

### 5.1 Client (`client-js`, browser)

```ts
const clasp = createClaspClient({ baseUrl });

await clasp.register(uid, password);          // init → [oprf] → Norm → Basalt(WASM) → KG → finalize
const session = await clasp.login(uid, password); // init → [oprf] → Norm → Basalt → Sign → verify
```

The password never leaves the device; only `pk` (registration) and `sig` (login) — plus a blinded OPRF element — cross the network.

### 5.2 Server (`server-node`)

Framework-agnostic handlers plus an Express/Fetch adapter. Dependencies are injected as interfaces so deployments swap infrastructure without touching protocol logic:

```ts
const server = createClaspServer({
  storage,          // StorageAdapter
  nonceStore,       // NonceStore
  oprfKeyProvider,  // OprfKeyProvider | null (null = baseline)
  rateLimiter,      // RateLimiter
  serverSecret,     // for pseudo-salt + reg_token signing
});
```

---

## 6. Cross-cutting interfaces & policies

```ts
interface StorageAdapter {
  getUser(uid): Promise<UserRecord | null>;   // { uid, salt_c, basalt_version, oprf_key_version, pk }
  createUser(record: UserRecord): Promise<void>; // fails if uid exists
  updateVerifier(uid, patch): Promise<void>;   // re-enrollment
}

interface NonceStore {                          // spec §6.1
  issue(uid): Promise<Nonce>;                   // 256-bit, TTL 60s, bound to uid
  consume(nonce, uid): Promise<boolean>;        // atomic fetch-and-delete
}

interface OprfKeyProvider {                      // spec §6.3
  currentVersion(): string;
  eval(version, blindedElement): Promise<Uint8Array>; // holds k_oprf; abstracts HSM/OPRF service
}

interface RateLimiter {
  check(key): Promise<void>;                     // hooked on init / oprf / verify
}
```

**Anti-enumeration & error model:**
- `login/init` returns an identical response shape for known and unknown `uid` (pseudo `salt_c = HMAC(server_secret, uid)`), with uniform timing.
- `login/verify` returns a uniform `401` for bad signature, unknown user, and consumed/expired nonce — no distinguishing messages.
- **Registration reveals existence** at `register/init` / `finalize` (a username cannot be registered twice); this is unavoidable and documented. Enumeration hardening is concentrated on the login path.
- Rate-limit `oprf/eval` (preserves the OPRF online-only property), `login/init` (nonce issuance), and `login/verify` (failure-rate backoff per `uid`/IP).

---

## 7. Interop test vectors (`vectors/`)

Shared JSON fixtures so any implementation can prove conformance:

- `norm.json` — `(pw, uid) → Norm`
- `basalt.json` — `(Norm, salt_c, version) → A`
- `keys.json` — `A → pk`, and `(A, message) → sig`
- `oprf.json` — blind/eval/unblind round trips with fixed randomness
- `transcript.json` — full registration + login transcripts (baseline and OPRF)

`client-js` and `server-node` both run these in CI; external ports validate against the same files.

---

## 8. Open build items

- [ ] Scaffold the Rust workspace (`clasp-core`, `clasp-wasm`) and pnpm workspace
- [ ] Select and pin the Argon2 crate + VOPRF crate versions and licenses
- [ ] Define the `reg_token` format (signed, short TTL) and session-token scheme
- [ ] Generate the first `vectors/` fixtures from `clasp-core`
- [ ] Native mobile bindings (deferred — web first)

---

## 9. References

- [CLASP Protocol Specification](clasp-spec.md)
- [Basalt Parameter Tuning](basalt-tuning.md)
- RFC 9497 — Oblivious Pseudorandom Functions (VOPRF)
- RFC 9106 — Argon2; RFC 5869 — HKDF
