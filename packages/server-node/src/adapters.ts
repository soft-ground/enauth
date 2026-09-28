// In-memory reference adapters for CLASP server infrastructure.
//
// For development, tests, and examples only — not for production (state is
// process-local and lost on restart). Swap in Redis-backed / DB-backed
// implementations of the same interfaces for real deployments (spec §6.1).

import { randomBytes } from "node:crypto";
import type { NonceStore, RateLimiter, StorageAdapter, UserRecord } from "./index.js";

export class InMemoryStorage implements StorageAdapter {
  private readonly users = new Map<string, UserRecord>();

  async getUser(uid: string): Promise<UserRecord | null> {
    return this.users.get(uid) ?? null;
  }

  async createUser(record: UserRecord): Promise<void> {
    if (this.users.has(record.uid)) throw new Error("user already exists");
    this.users.set(record.uid, record);
  }

  async updateVerifier(uid: string, patch: Partial<UserRecord>): Promise<void> {
    const existing = this.users.get(uid);
    if (!existing) throw new Error("user not found");
    this.users.set(uid, { ...existing, ...patch, uid });
  }
}

export class InMemoryNonceStore implements NonceStore {
  private readonly nonces = new Map<string, { uid: string; exp: number }>();

  constructor(
    private readonly ttlMs = 60_000,
    private readonly maxEntries = 100_000,
  ) {}

  async issue(uid: string): Promise<Uint8Array> {
    // Bound memory: unconsumed nonces are otherwise never removed, so a flood of
    // login/init calls would grow the map without limit. In production use a
    // store with native TTL eviction (e.g. Redis SET ... EX).
    if (this.nonces.size >= this.maxEntries) this.sweep();
    const nonce = new Uint8Array(randomBytes(32));
    const key = Buffer.from(nonce).toString("base64url");
    this.nonces.set(key, { uid, exp: Date.now() + this.ttlMs });
    return nonce;
  }

  async consume(nonce: Uint8Array, uid: string): Promise<boolean> {
    const key = Buffer.from(nonce).toString("base64url");
    const entry = this.nonces.get(key);
    // Single-threaded event loop makes get+delete effectively atomic.
    if (!entry) return false;
    this.nonces.delete(key);
    return entry.uid === uid && entry.exp >= Date.now();
  }

  private sweep(): void {
    const now = Date.now();
    for (const [key, entry] of this.nonces) {
      if (entry.exp < now) this.nonces.delete(key);
    }
    // Hard cap: under a flood of still-valid nonces, evict oldest first.
    while (this.nonces.size >= this.maxEntries) {
      const oldest = this.nonces.keys().next().value;
      if (oldest === undefined) break;
      this.nonces.delete(oldest);
    }
  }
}

/** Permissive limiter for development. Replace with a real token-bucket limiter. */
export class NoopRateLimiter implements RateLimiter {
  async check(_key: string): Promise<void> {
    /* no-op */
  }
}
