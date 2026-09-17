// CLASP reference server SDK. See docs/implementation-design.md §5.2 and §6.
//
// Infrastructure is injected as interfaces so deployments can swap storage,
// nonce store, OPRF key provider, and rate limiter without touching protocol logic.

export interface UserRecord {
  uid: string;
  saltC: Uint8Array;
  basaltVersion: string;
  oprfKeyVersion: string; // "none" for baseline deployments
  pk: Uint8Array;
}

export interface StorageAdapter {
  getUser(uid: string): Promise<UserRecord | null>;
  createUser(record: UserRecord): Promise<void>; // must fail if uid already exists
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
  oprfKeyProvider?: OprfKeyProvider | null; // null = baseline (no OPRF)
  rateLimiter: RateLimiter;
  serverSecret: Uint8Array; // pseudo-salt (anti-enumeration) + reg_token signing
}

export function createClaspServer(_opts: ClaspServerOptions) {
  return {
    // Handlers for /clasp/v1/* — TODO (register/init+finalize, oprf/eval,
    // login/init+verify, reenroll).
  };
}
