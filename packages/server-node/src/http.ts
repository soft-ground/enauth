// Minimal Node HTTP adapter that routes the CLASP endpoints to the handlers
// returned by createClaspServer. Framework-agnostic reference; adapt to Express,
// Fastify, etc. as needed.

import type { IncomingMessage, ServerResponse } from "node:http";
import type { HandlerResult, createClaspServer } from "./index.js";

type ClaspServer = ReturnType<typeof createClaspServer>;
type Handler = (body: unknown) => Promise<HandlerResult>;

const ROUTES: Record<string, keyof ClaspServer> = {
  "/clasp/v1/register/init": "registerInit",
  "/clasp/v1/register/finalize": "registerFinalize",
  "/clasp/v1/login/init": "loginInit",
  "/clasp/v1/login/verify": "loginVerify",
  "/clasp/v1/oprf/eval": "oprfEval",
};

// CLASP request bodies are tiny (a uid, a token, a few base64url blobs).
const MAX_BODY_BYTES = 64 * 1024;

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).length;
    if (total > MAX_BODY_BYTES) {
      req.destroy();
      throw Object.assign(new Error("payload too large"), { status: 413 });
    }
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

/** Build a Node `(req, res)` request listener for the given CLASP server. */
export function createRequestListener(server: ClaspServer) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (req.method !== "POST") return sendJson(res, 405, { error: "method not allowed" });

    const path = (req.url ?? "").split("?")[0];
    const handlerName = ROUTES[path];
    if (!handlerName) return sendJson(res, 404, { error: "not found" });

    try {
      const body = await readJson(req);
      const handler = server[handlerName] as unknown as Handler;
      const result = await handler(body);
      sendJson(res, result.status, result.body);
    } catch (err) {
      const status =
        err && typeof err === "object" && typeof (err as { status?: unknown }).status === "number"
          ? (err as { status: number }).status
          : 400;
      sendJson(res, status, { error: status === 413 ? "payload too large" : "bad request" });
    }
  };
}
