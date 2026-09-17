// End-to-end test for the CLASP-OPRF profile.
//
// Uses the nodejs-target clasp-wasm build for BOTH the client derivation and
// the server's OPRF evaluation, so the VOPRF encoding is guaranteed compatible
// (same Rust `voprf` crate on both sides). Prerequisite:
//   wasm-pack build core/clasp-wasm --target nodejs --out-dir pkg-node

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";
import { buildAuthMessage, createClaspServer, type OprfKeyProvider } from "./index.js";
import { InMemoryNonceStore, InMemoryStorage, NoopRateLimiter } from "./adapters.js";

const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const wasm: any = require("../../../core/clasp-wasm/pkg-node/clasp_wasm.js");

const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
const unb64u = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64url"));

/** Reference OPRF key provider backed by the WASM VOPRF (single key). */
class WasmOprfKeyProvider implements OprfKeyProvider {
  private readonly key: Uint8Array = wasm.oprf_generate_key();
  constructor(private readonly version = "oprf-v1") {}
  currentVersion(): string {
    return this.version;
  }
  async eval(_version: string, blinded: Uint8Array): Promise<Uint8Array> {
    return wasm.oprf_eval(this.key, blinded);
  }
}

function makeOprfServer() {
  return createClaspServer({
    storage: new InMemoryStorage(),
    nonceStore: new InMemoryNonceStore(),
    oprfKeyProvider: new WasmOprfKeyProvider(),
    rateLimiter: new NoopRateLimiter(),
    serverSecret: new Uint8Array(32).fill(9),
  });
}

test("CLASP-OPRF register + login round trip", async () => {
  const server = makeOprfServer();
  const uid = "erin@example.com";
  const password = new TextEncoder().encode("hunter2");
  const uidBytes = new TextEncoder().encode(uid);

  // --- Registration ---
  const init = await server.registerInit({ uid });
  const reg = init.body as {
    salt_c: string;
    basalt_version: string;
    oprf_key_version: string;
    reg_token: string;
  };
  assert.equal(reg.oprf_key_version, "oprf-v1");

  const br = wasm.oprf_blind(password, uidBytes);
  const e1 = await server.oprfEval({ uid, blinded_element: b64u(br.blinded), phase: "register" });
  const evaluated1 = unb64u((e1.body as { evaluated_element: string }).evaluated_element);
  const pk: Uint8Array = wasm.oprf_derive_public_key(
    br.state,
    password,
    uidBytes,
    unb64u(reg.salt_c),
    reg.basalt_version,
    evaluated1,
  );
  const fin = await server.registerFinalize({ reg_token: reg.reg_token, pk: b64u(pk) });
  assert.equal(fin.status, 201);

  // --- Login ---
  const li = await server.loginInit({ uid });
  const lo = li.body as { salt_c: string; basalt_version: string; nonce: string };

  const br2 = wasm.oprf_blind(password, uidBytes);
  const e2 = await server.oprfEval({ uid, blinded_element: b64u(br2.blinded), phase: "login" });
  const evaluated2 = unb64u((e2.body as { evaluated_element: string }).evaluated_element);
  const message = buildAuthMessage(uid, unb64u(lo.nonce));
  const sig: Uint8Array = wasm.oprf_derive_and_sign(
    br2.state,
    password,
    uidBytes,
    unb64u(lo.salt_c),
    lo.basalt_version,
    evaluated2,
    message,
  );
  const verify = await server.loginVerify({ uid, nonce: lo.nonce, sig: b64u(sig) });
  assert.equal(verify.status, 200);
  assert.equal((verify.body as { session: { uid: string } }).session.uid, uid);
});

test("CLASP-OPRF login fails with the wrong password", async () => {
  const server = makeOprfServer();
  const uid = "frank";
  const uidBytes = new TextEncoder().encode(uid);
  const good = new TextEncoder().encode("correct-password");
  const bad = new TextEncoder().encode("wrong-password");

  // Register with the good password.
  const init = await server.registerInit({ uid });
  const reg = init.body as { salt_c: string; basalt_version: string; reg_token: string };
  const br = wasm.oprf_blind(good, uidBytes);
  const e1 = await server.oprfEval({ uid, blinded_element: b64u(br.blinded), phase: "register" });
  const evaluated1 = unb64u((e1.body as { evaluated_element: string }).evaluated_element);
  const pk = wasm.oprf_derive_public_key(
    br.state,
    good,
    uidBytes,
    unb64u(reg.salt_c),
    reg.basalt_version,
    evaluated1,
  );
  await server.registerFinalize({ reg_token: reg.reg_token, pk: b64u(pk) });

  // Try to log in with the wrong password.
  const li = await server.loginInit({ uid });
  const lo = li.body as { salt_c: string; basalt_version: string; nonce: string };
  const br2 = wasm.oprf_blind(bad, uidBytes);
  const e2 = await server.oprfEval({ uid, blinded_element: b64u(br2.blinded), phase: "login" });
  const evaluated2 = unb64u((e2.body as { evaluated_element: string }).evaluated_element);
  const message = buildAuthMessage(uid, unb64u(lo.nonce));
  const sig = wasm.oprf_derive_and_sign(
    br2.state,
    bad,
    uidBytes,
    unb64u(lo.salt_c),
    lo.basalt_version,
    evaluated2,
    message,
  );
  const verify = await server.loginVerify({ uid, nonce: lo.nonce, sig: b64u(sig) });
  assert.equal(verify.status, 401);
});
