// Convenience loader for the generated clasp-wasm bindings.
//
// Prerequisite: build the bindings first with
//   wasm-pack build core/clasp-wasm --target web
// which produces the `clasp-wasm` package under core/clasp-wasm/pkg. Link it
// into your app (workspace dependency or bundler alias) so the import resolves.

import type { ClaspWasm } from "./index.js";

/**
 * Load and initialize the WASM module, returning a {@link ClaspWasm}.
 *
 * @param wasmUrl optional explicit URL to the `.wasm` binary; when omitted the
 * generated glue locates it relative to the module.
 */
export async function loadClaspWasm(wasmUrl?: string | URL): Promise<ClaspWasm> {
  const mod = await import("clasp-wasm");
  await mod.default(wasmUrl ? { module_or_path: wasmUrl } : undefined);
  return {
    derive_public_key: mod.derive_public_key,
    derive_and_sign: mod.derive_and_sign,
    oprf_blind: mod.oprf_blind,
    oprf_derive_public_key: mod.oprf_derive_public_key,
    oprf_derive_and_sign: mod.oprf_derive_and_sign,
  };
}
