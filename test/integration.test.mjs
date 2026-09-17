// End-to-end HTTP integration test: the real client-js SDK drives the real
// server-node handlers over an actual HTTP server, using the nodejs-target
// clasp-wasm build for the client crypto.
//
// Prerequisites (handled by `pnpm test:integration`):
//   - pnpm -r run build           (builds client-js and server-node to dist/)
//   - wasm-pack build core/clasp-wasm --target nodejs --out-dir pkg-node

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { test } from "node:test";

import { createClaspClient } from "../packages/client-js/dist/index.js";
import { createClaspServer } from "../packages/server-node/dist/index.js";
import {
  InMemoryNonceStore,
  InMemoryStorage,
  NoopRateLimiter,
} from "../packages/server-node/dist/adapters.js";
import { createRequestListener } from "../packages/server-node/dist/http.js";

const require = createRequire(import.meta.url);
const wasm = require("../core/clasp-wasm/pkg-node/clasp_wasm.js");

async function startServer(options) {
  const server = createClaspServer(options);
  const httpServer = createServer(createRequestListener(server));
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const { port } = httpServer.address();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => httpServer.close(resolve)),
  };
}

test("baseline: register + login over HTTP", async () => {
  const { baseUrl, close } = await startServer({
    storage: new InMemoryStorage(),
    nonceStore: new InMemoryNonceStore(),
    rateLimiter: new NoopRateLimiter(),
    serverSecret: new Uint8Array(32).fill(1),
  });
  try {
    const client = createClaspClient({ baseUrl, wasm });
    await client.register("alice", "correct-password");
    const session = await client.login("alice", "correct-password");
    assert.equal(session.session.uid, "alice");

    await assert.rejects(
      () => client.login("alice", "wrong-password"),
      /authentication failed/,
    );
  } finally {
    await close();
  }
});

test("OPRF: register + login over HTTP", async () => {
  const key = wasm.oprf_generate_key();
  const oprfKeyProvider = {
    currentVersion: () => "oprf-v1",
    eval: async (_version, blinded) => wasm.oprf_eval(key, blinded),
  };
  const { baseUrl, close } = await startServer({
    storage: new InMemoryStorage(),
    nonceStore: new InMemoryNonceStore(),
    oprfKeyProvider,
    rateLimiter: new NoopRateLimiter(),
    serverSecret: new Uint8Array(32).fill(2),
  });
  try {
    const client = createClaspClient({ baseUrl, wasm });
    await client.register("bob", "hunter2");
    const session = await client.login("bob", "hunter2");
    assert.equal(session.session.uid, "bob");

    await assert.rejects(() => client.login("bob", "not-hunter2"), /authentication failed/);
  } finally {
    await close();
  }
});
