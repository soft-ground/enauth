# CLASP Protocol Specification

**CLASP** — *Client-side Load-shifted Authentication via Split Proof*

| | |
|---|---|
| Status | Draft |
| Version | 0.1 |
| Date | 2026-09-14 |
| Author | soft-ground |
| Product | enauth |

---

## 0. Overview

CLASP is a password-authentication protocol that **shifts the heavy memory-hard computation to the client** while the server performs **only lightweight verification**.

The design philosophy in one sentence:

> The server no longer stores or compares a *password-equivalent* value.
> It stores only a *public verifier*, and the client submits, on every login, a *proof of possession* bound to a one-time nonce.

This shift achieves three properties simultaneously:

1. **Server DoS resistance** — the server never performs memory-hard work. The only heavy computation on the authentication path is client-side.
2. **Pass-the-Hash / replay resistance** — the value crossing the network is bound to a one-time nonce, so a captured value cannot be reused.
3. **Database-leak resistance** — the stored value is a public key; even if leaked it cannot be used directly, and offline cracking cost remains that of Basalt (memory-hard).

CLASP is a minimal skeleton of the SRP/OPAQUE-family **asymmetric PAKE (aPAKE)**, expressed with a password-derived signing key, a nonce challenge-response, and an OPRF.

---

## 1. Terminology & Notation

### 1.1 Components

| Name | Definition |
|---|---|
| **enauth** | The product / repository (Enhanced authentication method) |
| **CLASP** | This protocol (the composition) |
| **Basalt** | The memory-hard KDF profile used by CLASP: a hardening wrapper over Argon2id (RFC 9106). See §2 |

### 1.2 Symbols

| Symbol | Meaning |
|---|---|
| `pw`, `uid` | User password, user identifier |
| `salt_c` | Per-user client salt (128-bit, stored by server) |
| `Norm(pw, uid)` | Fixed-length normalized preimage (§2.1) |
| `Basalt(x, salt_c)` | The Basalt KDF, output is a 32-byte `A` (§2) |
| `A` | Basalt result (32 bytes, high-entropy seed) |
| `(sk, pk) = KG(A)` | Ed25519 key pair seeded by `A`: `sk = A`, `pk = A·G` |
| `n` | Server-issued nonce (256-bit, single-use, with TTL) |
| `Sign(sk, m)` / `Verify(pk, m, σ)` | Ed25519 signing / verification |
| `σ` | Client proof-of-possession signature |
| `H` | Fast hash (SHA-256/512) |
| `‖` | Byte concatenation |
| `G` | Ed25519 base point |

**Server-stored value:** `{ uid : (salt_c, basalt_version, oprf_key_version, pk) }`
(`oprf_key_version = none` for baseline deployments; see §3.3).
The server stores **none** of `pw`, `A`, or `sk`.

---

## 2. Basalt — Memory-Hard KDF Profile

Basalt is **not** a new cryptographic primitive. It is a usage profile that wraps the vetted Argon2id (RFC 9106) in a **fixed hardening configuration**.

```
Basalt(x, salt_c):
    return Argon2id(x, salt_c; m = M, t = T, p = P, outLen = 32)
```

### 2.1 Fixed-Length Preimage (Norm)

To prevent the password length from leaking through timing, the Basalt input is always normalized to 32 bytes.

```
Norm(pw, uid) = HKDF-SHA512( ikm = pw, salt = uid, info = "enauth/basalt/v1" )[:32]
```

- The input length is always 32 bytes regardless of `pw` length, eliminating the length-based timing channel.
- Domain separation via `info` avoids "password shucking" (fast-hash preimage reuse attacks).
- Using `uid` as the salt makes the preimage differ per user even for identical passwords.

### 2.2 Parameters `(M, T, P)`

- These are fixed constants, **independent of user input** (a precondition for constant-time behavior).
- **Basalt-v1 (provisional):** `M = 65536 KiB (64 MiB)`, `T = 3`, `P = 1`, `salt_c = 16 bytes`, `outLen = 32 bytes`. Values are pending empirical validation — see [Basalt Parameter Tuning](basalt-tuning.md).
- Parameters are **pinned at registration** and stored as `(salt_c, basalt_version, pk)`; every login re-runs the same parameters so that `A` is reproducible. A `basalt_version` tag enables later migration (e.g., `Basalt-v2`) via authenticated verifier re-enrollment.

> **License / attribution notice:** Basalt is built on the Argon2id memory-hard function (RFC 9106), whose reference implementation is dual-licensed CC0-1.0 / Apache-2.0. CLASP/Basalt reuses this primitive and does not implement a memory-hard primitive of its own.

---

## 3. The CLASP Protocol

### 3.1 Registration — zero memory-hard work on the server

```
Client                                   Server
  │  -- register_init(uid) ----------->    │
  │                                         │  salt_c <- Random(128b)          [light]
  │  <------------ salt_c --------------    │
  │                                         │
  │  x  = Norm(pw, uid)          [fixed len]│
  │  A  = Basalt(x, salt_c)      *HEAVY (client)
  │  pk = A · G   (Ed25519 public key)      │
  │                                         │
  │  -- register_finalize(uid, pk) --->     │
  │                                         │  store {uid : (salt_c, pk)}      [light]
  │  <------------ 201 OK --------------    │
```

### 3.2 Login — the server does one signature verification only

```
Client                                   Server
  │  -- login_init(uid) ------------->      │
  │                                         │  n <- Random(256b), TTL=30s      [light]
  │                                         │  nonces[n] = (uid, now, unused)
  │  <-------- (salt_c, n) --------------   │
  │                                         │
  │  x  = Norm(pw, uid)                     │
  │  A  = Basalt(x, salt_c)      *HEAVY (client)
  │  sk = A                                 │
  │  σ  = Sign(sk, "AUTH" ‖ uid ‖ n)        │
  │                                         │
  │  -- login_verify(uid, n, σ) ------>     │
  │                                         │  assert nonces[n].unused AND not expired
  │                                         │  ok = Verify(pk, "AUTH"‖uid‖n, σ)  *light (µs)
  │                                         │  consume(n)   // block reuse
  │  <-------- session / 401 -----------    │
```

**Nonce-signature property:** the value `σ` crossing the wire is deterministically bound to `n`. For distinct nonces `n₁ ≠ n₂`:

```
Pr[ Verify(pk, "AUTH"‖uid‖n₂, σ(n₁)) = 1 ]  ≈  signature-forgery hardness (negligible)
```

Therefore a captured `σ` is useless in any subsequent session.

### 3.3 CLASP-OPRF — Optional Hardening Profile

Baseline CLASP already resists a database leak: the stored `pk` is a public key (ECDLP-hard to invert) and each offline guess costs a full `Basalt` evaluation with a per-user salt — equivalent to best-practice server-side Argon2id storage. However, client-side memory-hardness is capped by the weakest login device (see [Basalt tuning §3](basalt-tuning.md)), so this ceiling can be lower than a server could otherwise afford. **CLASP-OPRF** removes that ceiling by mixing a server-held secret into the derivation, independently of client device capability.

This is a **decided, first-class optional profile** — not a mandatory part of CLASP — so that low-ops deployments can run baseline while production deployments opt in. Adoption is **recommended for production**.

**Derivation with OPRF** (inserted between `Norm` and `Basalt`):

```
  x    = Norm(pw, uid)
  b, B = Blind(x)                          // client-side blinding
  -- oprf_eval(uid, B) --------->  Server:  R = k_oprf[v] · B   [light scalar mult]
  <-------- (R, v) --------------           // v = oprf_key_version
  rw = Unblind(R, b)                        // value mixed with server secret k_oprf[v]
  A  = Basalt(rw, salt_c)
```

Use a standardized VOPRF construction (RFC 9497, e.g., over ristretto255).

**Security effect:** if the database (`salt_c`, `pk`) leaks but `k_oprf` does not, offline dictionary attack becomes infeasible — every guess requires an online `oprf_eval` call and is therefore rate-limitable. Keep `k_oprf` in a KMS/HSM, separate from the user database, so that two independent breaches are required.

**Server cost:** one scalar multiplication (≈ µs) per `oprf_eval`, negligible versus Basalt and consistent with the DoS-resistance goal. Rate-limit `oprf_eval` per `uid` / IP.

**Key management & versioning:**
- Each user row stores `oprf_key_version` (`none` for baseline). Rotating `k_oprf` changes `rw → A → pk`, so it cannot be done in place.
- Maintain a keyring of versioned keys. To rotate, or to enable OPRF for an existing baseline user, **re-enroll the verifier opportunistically on the user's next successful login**: the authenticated client re-derives `A` under the new key version and uploads a fresh `pk`. This avoids a flag-day migration and reuses the same mechanism as `Basalt-v2` migration (§2.2).
- **Availability:** once enabled, `k_oprf` is required for authentication, so the OPRF/key service must be highly available.

---

## 4. Timing-Attack-Resistant Client Structure

Formal goal: the client's total computation time `T` must be a function of public parameters only.

```
T = f(M, T_iter, P, |x|)        with   ∂T/∂(pw value) = ∂T/∂(pw length) = 0
```

A five-part structure satisfies this:

1. **Fixed-length preimage** — `Norm` always yields 32 bytes, eliminating password-length leakage (§2.1).
2. **Data-independent memory access** — Argon2**id**'s first half is data-independent (side-channel resistant); parameters are fixed constants independent of the user.
3. **Branch-free post-processing** — `sk = A`, `pk = A·G`, and `Sign` all use constant-time libraries (e.g., libsodium `crypto_sign`); no secret-dependent early returns.
4. **Constant-time comparison** — all equality checks use `sodium_memcmp`-style routines. (Server verification is signature verification, with no secret-dependent branch.)
5. **WASM core** — run the Basalt core in WASM (with a fixed memory buffer) to avoid JS JIT/GC variance.

> **Residual risk (an honest limit):** browsers run on shared hardware (cache, SMT, Spectre-class channels) and JIT, so a "mathematically perfect" constant time is practically unreachable. This structure removes the *first-order timing channel with respect to the secret's value and length*; residual microarchitectural channels are to be *documented and accepted*, not claimed as eliminated.

---

## 5. Security Analysis

### 5.1 Threat A — Pass-the-Hash / Replay

**Attack:** a MITM or logging proxy captures the authentication value from login traffic and replays it.

**Why a naive design fails:** storing `V = H(A)` and sending `A` in the clear makes `A` itself the credential, so `replay(A) → H(A)=V → pass`. Since `A` is a static, session-independent value, reuse succeeds.

**CLASP defenses:**
- **Nonce-bound signature** `σ = Sign(A, "AUTH"‖uid‖n)`. The server manages `n` as single-use with a TTL and calls `consume(n)` after verification.
- **Single-use + expiry** — `nonces[n]` is a state machine `{unused → consumed}`; resubmission is rejected on state mismatch.
- **Channel binding (stronger)** — additionally binding a TLS exporter value into `σ` (`… ‖ tls_exporter`) blocks replay outside the originating session.
- Result: no long-lived credential ever exists on the network.

### 5.2 Threat B — Offline Dictionary Attack after DB Leak & User Enumeration

**Attack:** `(salt_c, pk)` leaks from the database, enabling offline cracking with a dictionary `D`; or a pre-login `salt_c` endpoint is used to detect account existence.

**CLASP defenses:**
- **Non-recoverability** — the stored value is `pk = A·G`; recovering `A` is ECDLP-hard, i.e., practically infeasible.
- **Preserved cost floor** — each offline guess costs one `Basalt` (memory-hard) evaluation. Moving the computation to the client keeps offline resistance identical to server-side storage. Per-user `salt_c` blocks precomputation amortization.
- **Enumeration blocking** — return a deterministic pseudo-random salt for unknown `uid` as well: `salt_c = HMAC(server_secret, uid)`, making registered and unregistered accounts indistinguishable. Keep `login_init` response time and shape uniform.
- **Ceiling removal via OPRF (§3.3)** — if `k_oprf` does not leak, offline attack cost is effectively unbounded (each guess requires an online server call).

### 5.3 Threat C — Residual DoS and Trust-Shift

Moving heavy computation to the client removes server-side Argon2id DoS but introduces new surfaces.

1. **Endpoint amplification** — flooding `login_init` / `oprf_eval`.
   → Both operations are O(1) and lightweight. Place a **rate limiter (token bucket) plus an optional proof-of-work** in front of nonce issuance. Enforce the invariant that **no memory-hard work exists anywhere on the server** authentication path.
2. **Garbage `σ` flooding** — sending large volumes of meaningless signatures.
   → Server cost is one `Verify` (≈ µs); failures terminate cheaply. Apply failure-rate-based backoff per `uid` / IP.
3. **Malicious / lightweight client (skipping the work)** — using a custom client that skips Basalt.
   → Registering an arbitrary `pk` is possible, but login still requires the correct `pw → A → sk`. Skipping only weakens the **attacker's own account** and does not harm protocol integrity. Note that offline cracking runs on the attacker's own hardware, so `(M, T, P)` must be set as a **security bound**, not tuned to low-end clients.

### 5.4 Summary

| Threat | Naive client-side hashing | CLASP |
|---|---|---|
| Server DoS | Defended (core goal) | Defended + residual surfaces closed |
| Pass-the-Hash / replay | Vulnerable (static `A` sent) | Nonce-bound signature + single-use |
| DB-leak reuse | Vulnerable (`H(A)` replayed) | Public key stored, replay impossible |
| Offline dictionary | Basalt cost retained | Same + ceiling removed via OPRF |
| Timing / length leakage | Implementation-dependent | Fixed preimage + Argon2id + WASM |

---

## 6. Operational Requirements

### 6.1 Nonce store

- **Nonce `n`:** 256-bit CSPRNG output, bound to `uid` at issuance, single-use, with a TTL.
- **TTL:** 60 s recommended (range 30–120 s), balancing clock skew and login UX against the replay window.
- **Storage:** a store shared across all server instances (e.g., Redis), since `login_init` and `login_verify` may be handled by different instances. Key = `n`, value = `(uid, issued_at)`, with store-level TTL for automatic expiry.
- **Atomic consume:** `login_verify` MUST atomically fetch-and-delete (compare-and-delete) the nonce so concurrent requests cannot use it twice — this closes the replay race in §5.1. Reject if the nonce is absent or expired.
- **Binding:** reject if the nonce was not issued for the presented `uid`. (The signature is checked against `"AUTH"‖uid‖n`, so a cross-`uid` nonce cannot validate; reject early regardless.)
- Stateless (MAC-signed) nonces are possible but still require a consumed-set for strict single-use, so the stateful store is the recommended default.

### 6.2 Channel binding (TLS exporter)

- Binding a TLS exporter value (RFC 9266 `tls-exporter`, TLS 1.3) into `σ` — i.e. `σ = Sign(sk, "AUTH"‖uid‖n‖tls_exporter)` — blocks replay even against an in-session TLS termination/MITM (§5.1).
- **Browser limitation (honest):** standard browser JavaScript cannot access the TLS exporter, so channel binding is available only to **native/mobile clients** (or other non-browser environments) that can read it.
- **Decision:** channel binding is **optional and platform-gated** — enable it where the client platform exposes the exporter; web clients rely on nonce single-use + TTL + TLS transport. It is NOT mandatory, as that would exclude web clients.

### 6.3 OPRF key infrastructure (`CLASP-OPRF` deployments)

- `k_oprf` MUST live outside the user database, so that a database leak alone does not expose it.
- **KMS/HSM caveat (honest):** typical cloud KMS/HSM products do not natively perform ristretto255 scalar multiplication, so `k_oprf` usually cannot remain entirely inside a KMS. Recommended pattern: hold `k_oprf` in a hardened, access-restricted OPRF service (in memory), sealed/wrapped at rest by a KMS and unwrapped only in that service's memory. Use an EC-capable HSM only if it supports the chosen group.
- **Keyring:** map `oprf_key_version → key`; retain retired versions until all users have migrated off them (§7).
- **High availability:** when enabled, `oprf_eval` sits on the authentication path — the service MUST be HA, since an outage blocks all logins.
- **Rate limiting:** rate-limit `oprf_eval` per `uid` / IP to preserve the online-only property that makes offline attack infeasible.

---

## 7. Versioning & Migration

Each user row carries two independent version tags: `basalt_version` (the Basalt KDF profile, §2.2) and `oprf_key_version` (the OPRF key, §3.3; `none` for baseline).

Any change to a version tag changes the derived `A`, hence `sk` / `pk`, and therefore requires re-deriving the verifier with the user's password. A single mechanism handles all such changes:

1. **New registrations** always use the current versions.
2. **Opportunistic upgrade on login** — after a user authenticates successfully under their stored versions, if newer versions exist, the authenticated client re-derives `A` under the new version(s) and uploads a fresh `pk` within the same authenticated session. No password re-prompt is needed (the password is already in hand during login).
3. **Forced re-enrollment** — to retire an old version, set a deadline; users still on the retired version after the deadline must re-enroll explicitly (password re-entry) at next login. Retire old Basalt parameters / OPRF keys only after migration completes or the deadline passes.
4. **Forward only** — versions are never downgraded.

This covers `Basalt-v1 → Basalt-v2` parameter upgrades and OPRF enable/rotate uniformly.

---

## 8. Open Items

Design decisions are settled below; remaining items are execution/provisioning tasks.

- [ ] **(execution)** Measure and finalize Basalt parameters `(M, T, P)` on real reference devices — methodology in [Basalt tuning §5](basalt-tuning.md)
- [ ] **(execution)** Provision `k_oprf` infrastructure per §6.3 (for `CLASP-OPRF` deployments)
- [x] OPRF adoption — optional `CLASP-OPRF` profile, recommended for production (§3.3)
- [x] Channel-binding scope — optional, platform-gated (§6.2)
- [x] Nonce store design and TTL — distributed store, atomic consume, 60 s TTL (§6.1)
- [x] Versioning & migration policy — unified opportunistic re-enrollment (§7)

---

## 9. References

- RFC 9106 — Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
- RFC 9807 / OPAQUE — Asymmetric PAKE (aPAKE) design reference
- RFC 9497 — Oblivious Pseudorandom Functions (OPRFs) using prime-order groups (VOPRF)
- RFC 5869 — HKDF
- OWASP Password Storage Cheat Sheet — Argon2id parameter guidance
- P-H-C/phc-winner-argon2 — Argon2 reference implementation (CC0-1.0 / Apache-2.0)
