// CLASP reference server SDK. See docs/implementation-design.md §5.2 and §6.
//
// Infrastructure is injected as interfaces so deployments can swap storage,
// nonce store, OPRF key provider, and rate limiter without touching protocol
// logic. Ed25519 verification uses @noble/curves (pure JS) — the server stays
// lightweight (no memory-hard work, no WASM).

import { createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

// ---------------------------------------------------------------------------
// Injected infrastructure interfaces
// ---------------------------------------------------------------------------

export interface UserRecord {
  uid: string;
  saltC: Uint8Array;
  basaltVersion: string;
  oprfKeyVersion: string; // "none" for baseline deployments
  pk: Uint8Array;
}

export interface StorageAdapter {
  getUser(uid: string): Promise<UserRecord | null>;
  createUser(record: UserRecord): Promise<void>; // must reject if uid already exists
  updateVerifier(uid: string, patch: Partial<UserRecord>): Promise<void>;
}

export interface NonceStore {
  issue(uid: string): Promise<Uint8Array>; // 256-bit, TTL ~60s, bound to uid
  consume(nonce: Uint8Array, uid: string): Promise<boolean>; // atomic fetch-and-delete
}

export interface OprfKeyProvider {
  currentVersion(): string;
  eval(version: string, blindedElement: Uint8Array): Promise<Uint8Array>;
}

export interface RateLimiter {
  check(key: string): Promise<void>; // hooked on init / oprf / verify
}

export interface ClaspServerOptions {
  storage: StorageAdapter;
  nonceStore: NonceStore;
  oprfKeyProvider?: OprfKeyProvider | null; // null/undefined = baseline (no OPRF)
  rateLimiter: RateLimiter;
  serverSecret: Uint8Array; // master secret; per-purpose subkeys derived via HKDF
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

export interface HandlerResult {
  status: number;
  body: unknown;
}

const BASALT_VERSION = "basalt-v1";
const REG_TOKEN_TTL_MS = 5 * 60 * 1000;

// ---------------------------------------------------------------------------
// Encoding (must match the client exactly)
// ---------------------------------------------------------------------------

const AUTH_DOMAIN = Buffer.from("CLASP-AUTH-v1", "utf8");

/** Canonical CLASP login message: "CLASP-AUTH-v1" ‖ u32be(len uid) ‖ uid ‖ nonce. */
export function buildAuthMessage(uid: string, nonce: Uint8Array): Uint8Array {
  const uidBytes = Buffer.from(uid, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(uidBytes.length, 0);
  return Buffer.concat([AUTH_DOMAIN, len, uidBytes, nonce]);
}

const b64u = {
  enc: (b: Uint8Array): string => Buffer.from(b).toString("base64url"),
  dec: (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64url")),
};

// ---------------------------------------------------------------------------
// reg_token: a short-lived signed token binding register/init to finalize
// ---------------------------------------------------------------------------

interface RegTokenPayload {
  uid: string;
  salt_c: string; // base64url
  bv: string;
  ov: string;
  exp: number;
}

function signRegToken(secret: Uint8Array, payload: RegTokenPayload): string {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const mac = createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${mac}`;
}

function verifyRegToken(secret: Uint8Array, token: string): RegTokenPayload | null {
  const dot = token.indexOf(".");
  if (dot < 0) return null;
  const body = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  const expected = createHmac("sha256", secret).update(body).digest();
  const got = Buffer.from(mac, "base64url");
  if (expected.length !== got.length || !timingSafeEqual(expected, got)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as RegTokenPayload;
    if (typeof payload.exp !== "number" || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

/** Deterministic pseudo-salt for unknown users (anti-enumeration, spec §5.2). */
function pseudoSalt(secret: Uint8Array, uid: string): Uint8Array {
  const mac = createHmac("sha256", secret).update(`salt|${uid}`).digest();
  return new Uint8Array(mac.subarray(0, 16));
}

function verifySignature(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, message, pk);
  } catch {
    return false;
  }
}

/** Domain-separated subkey from the server secret (HKDF-SHA256). */
function subkey(secret: Uint8Array, label: string): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, new Uint8Array(0), Buffer.from(label, "utf8"), 32));
}

// A fixed valid public key, used to run a constant-work verify for unknown
// users so login/verify timing does not reveal account existence.
const DUMMY_PK = ed25519.getPublicKey(new Uint8Array(32).fill(1));

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

export function createClaspServer(opts: ClaspServerOptions) {
  const oprfVersion = (): string => opts.oprfKeyProvider?.currentVersion() ?? "none";

  // Per-purpose subkeys so one secret is not reused across HMAC contexts.
  const kRegToken = subkey(opts.serverSecret, "clasp/reg-token/v1");
  const kSalt = subkey(opts.serverSecret, "clasp/pseudo-salt/v1");
  const kSession = subkey(opts.serverSecret, "clasp/session/v1");

  return {
    /** POST /clasp/v1/register/init */
    async registerInit(body: { uid?: string }): Promise<HandlerResult> {
      if (!body?.uid) return { status: 400, body: { error: "uid required" } };
      await opts.rateLimiter.check(`register:${body.uid}`);

      // Registration inherently reveals existence (a name cannot be taken twice).
      if (await opts.storage.getUser(body.uid)) {
        return { status: 409, body: { error: "already registered" } };
      }

      const saltC = new Uint8Array(randomBytes(16));
      const payload: RegTokenPayload = {
        uid: body.uid,
        salt_c: b64u.enc(saltC),
        bv: BASALT_VERSION,
        ov: oprfVersion(),
        exp: Date.now() + REG_TOKEN_TTL_MS,
      };
      return {
        status: 200,
        body: {
          salt_c: payload.salt_c,
          basalt_version: payload.bv,
          oprf_key_version: payload.ov,
          reg_token: signRegToken(kRegToken, payload),
        },
      };
    },

    /** POST /clasp/v1/register/finalize */
    async registerFinalize(body: { reg_token?: string; pk?: string }): Promise<HandlerResult> {
      if (!body?.reg_token || !body?.pk) {
        return { status: 400, body: { error: "reg_token and pk required" } };
      }
      const payload = verifyRegToken(kRegToken, body.reg_token);
      if (!payload) return { status: 400, body: { error: "invalid or expired reg_token" } };

      const record: UserRecord = {
        uid: payload.uid,
        saltC: b64u.dec(payload.salt_c),
        basaltVersion: payload.bv,
        oprfKeyVersion: payload.ov,
        pk: b64u.dec(body.pk),
      };
      try {
        await opts.storage.createUser(record);
      } catch {
        return { status: 409, body: { error: "already registered" } };
      }
      return { status: 201, body: { status: "ok" } };
    },

    /** POST /clasp/v1/login/init */
    async loginInit(body: { uid?: string }): Promise<HandlerResult> {
      if (!body?.uid) return { status: 400, body: { error: "uid required" } };
      await opts.rateLimiter.check(`login-init:${body.uid}`);

      // Uniform response for known and unknown uid (anti-enumeration). Always
      // compute the pseudo-salt so the HMAC work happens on both paths.
      const user = await opts.storage.getUser(body.uid);
      const fallbackSalt = pseudoSalt(kSalt, body.uid);
      const saltC = user ? user.saltC : fallbackSalt;
      const nonce = await opts.nonceStore.issue(body.uid);
      return {
        status: 200,
        body: {
          salt_c: b64u.enc(saltC),
          basalt_version: user?.basaltVersion ?? BASALT_VERSION,
          oprf_key_version: user?.oprfKeyVersion ?? oprfVersion(),
          nonce: b64u.enc(nonce),
        },
      };
    },

    /** POST /clasp/v1/login/verify */
    async loginVerify(body: {
      uid?: string;
      nonce?: string;
      sig?: string;
    }): Promise<HandlerResult> {
      if (!body?.uid || !body?.nonce || !body?.sig) {
        return { status: 400, body: { error: "uid, nonce, sig required" } };
      }
      await opts.rateLimiter.check(`login-verify:${body.uid}`);

      const unauthorized: HandlerResult = { status: 401, body: { error: "unauthorized" } };
      const nonce = b64u.dec(body.nonce);

      // Atomic single-use consume first: a captured nonce cannot be replayed.
      if (!(await opts.nonceStore.consume(nonce, body.uid))) return unauthorized;

      // Verify against a dummy key for unknown users too, so the Ed25519 work
      // runs on both paths and login/verify timing does not reveal existence.
      const user = await opts.storage.getUser(body.uid);
      const message = buildAuthMessage(body.uid, nonce);
      const ok = verifySignature(b64u.dec(body.sig), message, user ? user.pk : DUMMY_PK);
      if (!user || !ok) return unauthorized;

      // Minimal reference session token; real session management is deployment-defined.
      const issuedAt = Date.now();
      const token = createHmac("sha256", kSession)
        .update(`session|${user.uid}|${issuedAt}`)
        .digest("base64url");
      return { status: 200, body: { session: { uid: user.uid, token, issuedAt } } };
    },

    /** POST /clasp/v1/oprf/eval (CLASP-OPRF profile only) */
    async oprfEval(body: {
      uid?: string;
      blinded_element?: string;
      phase?: "register" | "login";
    }): Promise<HandlerResult> {
      if (!opts.oprfKeyProvider) {
        return { status: 400, body: { error: "OPRF profile not enabled" } };
      }
      if (!body?.uid || !body?.blinded_element) {
        return { status: 400, body: { error: "uid and blinded_element required" } };
      }
      await opts.rateLimiter.check(`oprf:${body.uid}`);

      // Register uses the current key; login uses the user's stored version
      // (unknown uid keeps the current version — uniform, anti-enumeration).
      let version = opts.oprfKeyProvider.currentVersion();
      if (body.phase === "login") {
        const user = await opts.storage.getUser(body.uid);
        if (user && user.oprfKeyVersion !== "none") version = user.oprfKeyVersion;
      }
      const evaluated = await opts.oprfKeyProvider.eval(version, b64u.dec(body.blinded_element));
      return {
        status: 200,
        body: { evaluated_element: b64u.enc(evaluated), oprf_key_version: version },
      };
    },
  };
}
