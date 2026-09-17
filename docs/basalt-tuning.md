# Basalt Parameter Tuning

Parameter selection and tuning methodology for the **Basalt** KDF profile used by [CLASP](clasp-spec.md).

| | |
|---|---|
| Status | Draft (provisional values, pending empirical validation) |
| Version | 0.1 |
| Date | 2026-09-14 |
| Author | soft-ground |
| Profile | Basalt-v1 |

---

## 1. Why client-side tuning differs from server-side

Basalt runs in the **client** (JS/WASM), which inverts the usual Argon2id tuning calculus.

| Aspect | Server-side (typical) | Basalt (client-side) |
|---|---|---|
| Who pays the memory cost | Server (concurrent logins × `m`) | **Each user's device, once** |
| Memory ceiling driver | Server RAM ÷ concurrency | **Weakest target device + browser WASM limit** |
| Parallelism `p` | Free use of server cores | Needs Web Workers + `SharedArrayBuffer` (COOP/COEP) → effectively **p=1** |
| Tuning basis | Server throughput | **UX latency budget + device variance** |

**Insight 1 — the server no longer pays the memory cost.** Because the per-login memory multiplication across concurrent server requests disappears, Basalt can afford *higher* memory than server-side storage would. The ceiling is no longer "server RAM" but "what the weakest target device tolerates."

---

## 2. Parameter pinning and the device-variance trap

`A` must be reproducible: `same pw + same salt_c + same (M,T,P) → same A → same sk → same pk`. Therefore parameters are **pinned at registration** and stored server-side as `(salt_c, basalt_version, pk)`, and **every subsequent login re-runs those exact parameters on whatever device the user is on**.

**Trap:** a user who registers on a powerful desktop and later logs in from a low-end phone must run the desktop-tier parameters on the phone — potentially very slow.

**Resolution:** v1 uses a **single global profile (`Basalt-v1`)** tuned so the *weakest expected login device* stays within the latency budget. This also satisfies the constant-time requirement (parameters are user-independent constants). A stored `basalt_version` enables later migration to `Basalt-v2` by re-enrolling the verifier during an authenticated session.

---

## 3. Insight 2 — client hardness is capped by the weakest device

Because memory-hardness is bounded by the weakest device, **the client KDF alone cannot raise security without limit.** To compensate for this ceiling, add defenses that are **independent of client capability**:

- **OPRF (server pepper)** — see [CLASP §3.3](clasp-spec.md). Removes the offline-dictionary ceiling regardless of client device speed.
- **Rate limiting** on nonce/OPRF issuance.

This is a strong argument for adopting the OPRF layer: it decouples security from client hardware, which is the fundamental limitation of client-side hashing.

---

## 4. Basalt-v1 — provisional profile

Decisions locked (2026-09-14): target device tier = **Balanced (64 MiB)**, parallelism = **p=1** (portable, no cross-origin isolation required).

| Parameter | Value | Notes |
|---|---|---|
| Algorithm | Argon2id, RFC 9106 (v1.3 / `0x13`) | Reused primitive; not re-implemented |
| Memory `M` | 65536 KiB (64 MiB) | Safe within mobile WASM limits; above OWASP minimum |
| Iterations `T` | 3 | Fill latency budget after maximizing memory |
| Parallelism `P` | 1 | Portable; no Workers/`SharedArrayBuffer` needed |
| Salt `salt_c` | 16 bytes (128-bit), per-user, server-issued | |
| Output length | 32 bytes | Ed25519 seed |
| Preimage | `Norm(pw, uid) = HKDF-SHA512(ikm=pw, salt=uid, info="enauth/basalt/v1")[:32]` | Fixed-length, domain-separated |

> **These latency figures are theoretical estimates and are NOT final.** They must be validated on real devices (§5). Rough guide: desktop ~0.2 s, mid-range phone ~0.5–1 s, low-end phone ~1.5–2.5 s.
>
> For GPU/ASIC resistance, prefer raising `M` over `T` (the attacker's bottleneck is memory bandwidth). 128 MiB was rejected for v1 because low-end/older mobile devices risk WASM allocation failure or OOM kill, which is unacceptable for a broadly public release.

---

## 5. Empirical validation procedure

The provisional values above must be confirmed before freezing `Basalt-v1`.

1. **Define a reference device set** — e.g., a high-end desktop, a mid-range phone, and a low-end/older phone as the floor.
2. **Fix the latency budget** — recommended: mid-tier target ≤ 700 ms, low-end worst case ≤ 2 s.
3. **Measurement harness** — in the actual WASM build, binary-search `M` while measuring p95 latency per device; pick the largest `M` that keeps the low-end device within budget, then spend the remaining budget on `T` (minimum `T ≥ 2`).
4. **Memory-stability check** — repeatedly verify no allocation failure or tab crash at the chosen `M` on the low-end device.
5. **Freeze** the confirmed values as `Basalt-v1` and record `basalt_version`.

---

## 6. Open Items

- [ ] Run the §5 measurement pass on real reference devices; confirm or adjust `M`/`T`
- [x] OPRF adoption decided — specified as the optional `CLASP-OPRF` profile, recommended for production ([CLASP §3.3](clasp-spec.md)); it offsets the client-hardness ceiling described in §3
- [ ] Choose the Argon2 WASM build/library and pin its version and license
- [ ] Define the `Basalt-v2` migration flow (authenticated verifier re-enrollment)

---

## 7. References

- RFC 9106 — Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
- OWASP Password Storage Cheat Sheet — Argon2id parameter guidance
- RFC 5869 — HKDF
