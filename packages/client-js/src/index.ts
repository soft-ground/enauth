// CLASP browser client SDK. See docs/implementation-design.md §5.1.
//
// The password never leaves the device; only `pk` (registration), `sig` (login),
// and (with the OPRF profile) a blinded element cross the network.
//
// The WASM crypto is injected as `ClaspWasm` so this SDK compiles and tests
// independently of the generated bindings. Use `loadClaspWasm` (./wasm) to
// obtain a real instance.

/** The subset of the generated clasp-wasm bindings this SDK uses. */
export interface ClaspWasm {
  derive_public_key(
    password: Uint8Array,
    uid: Uint8Array,
    salt_c: Uint8Array,
    version: string,
  ): Uint8Array;
  derive_and_sign(
    password: Uint8Array,
    uid: Uint8Array,
    salt_c: Uint8Array,
    version: string,
    message: Uint8Array,
  ): Uint8Array;
}

export interface ClaspClientOptions {
  baseUrl: string;
  wasm: ClaspWasm;
  /** Override the global `fetch` (e.g. for tests). */
  fetch?: typeof fetch;
}

/** Deployment-defined session payload returned by login/verify. */
export type Session = Record<string, unknown>;

interface InitResponse {
  salt_c: string; // base64url
  basalt_version: string;
  oprf_key_version: string; // "none" for baseline
}
interface RegisterInitResponse extends InitResponse {
  reg_token: string;
}
interface LoginInitResponse extends InitResponse {
  nonce: string; // base64url
}

const encoder = new TextEncoder();

// Canonical CLASP login message encoding (unambiguous; server must mirror it):
//   "CLASP-AUTH-v1" ‖ u32be(len(uid)) ‖ uid ‖ nonce
const AUTH_DOMAIN = encoder.encode("CLASP-AUTH-v1");

function buildAuthMessage(uid: string, nonce: Uint8Array): Uint8Array {
  const uidBytes = encoder.encode(uid);
  const out = new Uint8Array(AUTH_DOMAIN.length + 4 + uidBytes.length + nonce.length);
  let o = 0;
  out.set(AUTH_DOMAIN, o);
  o += AUTH_DOMAIN.length;
  new DataView(out.buffer).setUint32(o, uidBytes.length, false); // big-endian
  o += 4;
  out.set(uidBytes, o);
  o += uidBytes.length;
  out.set(nonce, o);
  return out;
}

export function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function requireBaseline(oprfKeyVersion: string): void {
  if (oprfKeyVersion !== "none") {
    throw new Error("CLASP-OPRF profile is not yet implemented in this client");
  }
}

export function createClaspClient(opts: ClaspClientOptions) {
  const doFetch = opts.fetch ?? fetch;
  const base = opts.baseUrl.replace(/\/$/, "");

  function postJson(path: string, body: unknown): Promise<Response> {
    return doFetch(`${base}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  return {
    /** Register a new account. init → derive pk (WASM) → finalize. */
    async register(uid: string, password: string): Promise<void> {
      const res = await postJson("/clasp/v1/register/init", { uid });
      if (!res.ok) throw new Error(`register/init failed: ${res.status}`);
      const init = (await res.json()) as RegisterInitResponse;
      requireBaseline(init.oprf_key_version);

      const pk = opts.wasm.derive_public_key(
        encoder.encode(password),
        encoder.encode(uid),
        fromBase64Url(init.salt_c),
        init.basalt_version,
      );

      const fin = await postJson("/clasp/v1/register/finalize", {
        reg_token: init.reg_token,
        pk: toBase64Url(pk),
      });
      if (!fin.ok) throw new Error(`register/finalize failed: ${fin.status}`);
    },

    /** Log in. init → derive A and sign the nonce (WASM) → verify. */
    async login(uid: string, password: string): Promise<Session> {
      const res = await postJson("/clasp/v1/login/init", { uid });
      if (!res.ok) throw new Error(`login/init failed: ${res.status}`);
      const init = (await res.json()) as LoginInitResponse;
      requireBaseline(init.oprf_key_version);

      const nonce = fromBase64Url(init.nonce);
      const message = buildAuthMessage(uid, nonce);
      const sig = opts.wasm.derive_and_sign(
        encoder.encode(password),
        encoder.encode(uid),
        fromBase64Url(init.salt_c),
        init.basalt_version,
        message,
      );

      const verify = await postJson("/clasp/v1/login/verify", {
        uid,
        nonce: init.nonce,
        sig: toBase64Url(sig),
      });
      if (verify.status === 401) throw new Error("authentication failed");
      if (!verify.ok) throw new Error(`login/verify failed: ${verify.status}`);
      return (await verify.json()) as Session;
    },
  };
}

// Re-exported so the message encoding can be shared/verified against the server.
export { buildAuthMessage };
