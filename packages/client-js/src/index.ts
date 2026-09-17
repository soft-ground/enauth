// CLASP browser client SDK. See docs/implementation-design.md §5.1.
//
// The password never leaves the device; only `pk` (registration), `sig` (login),
// and a blinded OPRF element cross the network.

export interface ClaspClientOptions {
  baseUrl: string;
}

export interface Session {
  // Deployment-defined session token(s).
  [key: string]: unknown;
}

export function createClaspClient(_opts: ClaspClientOptions) {
  return {
    /** init -> [oprf] -> Norm -> Basalt(WASM) -> KG -> finalize */
    async register(_uid: string, _password: string): Promise<void> {
      throw new Error("not yet implemented");
    },

    /** init -> [oprf] -> Norm -> Basalt -> Sign -> verify */
    async login(_uid: string, _password: string): Promise<Session> {
      throw new Error("not yet implemented");
    },
  };
}
