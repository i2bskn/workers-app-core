// The part of node:crypto that the package uses. @cloudflare/workers-types does not declare node: modules, and
// @types/node would bring the Node globals into every file. Workers provides node:crypto from the compatibility
// date 2026-08-04 (or with the nodejs_compat flag).
declare module "node:crypto" {
  interface ScryptOptions {
    N?: number;
    r?: number;
    p?: number;
    maxmem?: number;
  }
  function scrypt(
    password: Uint8Array,
    salt: Uint8Array,
    keylen: number,
    options: ScryptOptions,
    callback: (error: Error | null, derivedKey: Uint8Array) => void,
  ): void;
  const nodeCrypto: { scrypt: typeof scrypt };
  export default nodeCrypto;
  export { scrypt, type ScryptOptions };
}
