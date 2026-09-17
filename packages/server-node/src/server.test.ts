// End-to-end tests for the CLASP reference server.
//
// A client keypair is simulated with @noble (in real CLASP the keypair is
// derived from the password via Basalt); this exercises the full server
// protocol: message encoding, nonce lifecycle, verification, base64url.

import assert from "node:assert/strict";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519";
import { buildAuthMessage, createClaspServer } from "./index.js";
import { InMemoryNonceStore, InMemoryStorage, NoopRateLimiter } from "./adapters.js";

function makeServer() {
  return createClaspServer({
    storage: new InMemoryStorage(),
    nonceStore: new InMemoryNonceStore(),
    rateLimiter: new NoopRateLimiter(),
    serverSecret: new Uint8Array(32).fill(7),
  });
}

const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
const unb64u = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64url"));

async function registerClient(
  server: ReturnType<typeof createClaspServer>,
  uid: string,
): Promise<Uint8Array> {
  const sk = ed25519.utils.randomPrivateKey();
  const pk = ed25519.getPublicKey(sk);
  const init = await server.registerInit({ uid });
  assert.equal(init.status, 200);
  const regToken = (init.body as { reg_token: string }).reg_token;
  const fin = await server.registerFinalize({ reg_token: regToken, pk: b64u(pk) });
  assert.equal(fin.status, 201);
  return sk;
}

test("register + login round trip succeeds", async () => {
  const server = makeServer();
  const uid = "alice@example.com";
  const sk = await registerClient(server, uid);

  const li = await server.loginInit({ uid });
  assert.equal(li.status, 200);
  const nonceStr = (li.body as { nonce: string }).nonce;
  const message = buildAuthMessage(uid, unb64u(nonceStr));
  const sig = b64u(ed25519.sign(message, sk));

  const verify = await server.loginVerify({ uid, nonce: nonceStr, sig });
  assert.equal(verify.status, 200);
  assert.equal((verify.body as { session: { uid: string } }).session.uid, uid);
});

test("nonce is single-use (replay rejected)", async () => {
  const server = makeServer();
  const uid = "bob";
  const sk = await registerClient(server, uid);

  const li = await server.loginInit({ uid });
  const nonceStr = (li.body as { nonce: string }).nonce;
  const sig = b64u(ed25519.sign(buildAuthMessage(uid, unb64u(nonceStr)), sk));

  assert.equal((await server.loginVerify({ uid, nonce: nonceStr, sig })).status, 200);
  assert.equal((await server.loginVerify({ uid, nonce: nonceStr, sig })).status, 401);
});

test("wrong signature rejected", async () => {
  const server = makeServer();
  const uid = "carol";
  await registerClient(server, uid);

  const li = await server.loginInit({ uid });
  const nonceStr = (li.body as { nonce: string }).nonce;
  const badSig = b64u(new Uint8Array(64)); // all-zero signature
  assert.equal((await server.loginVerify({ uid, nonce: nonceStr, sig: badSig })).status, 401);
});

test("unknown uid login/init returns a uniform shape (anti-enumeration)", async () => {
  const server = makeServer();
  const res = await server.loginInit({ uid: "nobody@nowhere" });
  assert.equal(res.status, 200);
  const body = res.body as { salt_c: string; nonce: string; oprf_key_version: string };
  assert.ok(body.salt_c.length > 0);
  assert.ok(body.nonce.length > 0);
  assert.equal(body.oprf_key_version, "none");
});

test("duplicate registration rejected", async () => {
  const server = makeServer();
  const uid = "dave";
  await registerClient(server, uid);
  const again = await server.registerInit({ uid });
  assert.equal(again.status, 409);
});
