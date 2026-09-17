// Ambient declaration for the generated (gitignored) clasp-wasm bindings, so
// this package typechecks without the pkg present. The real module is produced
// by `wasm-pack build core/clasp-wasm --target web` (core/clasp-wasm/pkg).
declare module "clasp-wasm" {
  export default function init(
    input?: { module_or_path: string | URL },
  ): Promise<unknown>;

  export function derive_public_key(
    password: Uint8Array,
    uid: Uint8Array,
    salt_c: Uint8Array,
    version: string,
  ): Uint8Array;

  export function derive_and_sign(
    password: Uint8Array,
    uid: Uint8Array,
    salt_c: Uint8Array,
    version: string,
    message: Uint8Array,
  ): Uint8Array;
}
