import nodeCrypto from "node:crypto";
import { base64UrlDecode, base64UrlEncode } from "./tokens.js";

// Cloudflare Workers rejects PBKDF2 above 100,000 iterations in production (on every plan), while local workerd
// accepts it. Also the upper bound of the iterations accepted from a stored hash.
export const MAX_PBKDF2_ITERATIONS = 100000;
// Guards against a misconfiguration that would create very weak hashes.
export const MIN_PBKDF2_ITERATIONS = 10000;
export const DEFAULT_PBKDF2_ITERATIONS = 100000;
const PBKDF2_ALGORITHM = "pbkdf2_sha256";
const SALT_BYTES = 16;
const HASH_BYTES = 32;

// The scrypt parameters of new hashes (one of the OWASP recommendations, 8 MiB of memory). Not configurable.
export const SCRYPT_N = 8192;
export const SCRYPT_R = 8;
export const SCRYPT_P = 10;
const SCRYPT_ALGORITHM = "scrypt";
const SCRYPT_MAXMEM = 64 * 1024 * 1024;
// Bounds of the parameters accepted from a stored hash, so that a corrupted value cannot start a heavy computation.
const SCRYPT_MIN_N = 2 ** 10;
const SCRYPT_MAX_N = 2 ** 16;
const SCRYPT_MAX_R = 16;
const SCRYPT_MAX_P = 16;
// The memory of 128 * N * r bytes, with room below SCRYPT_MAXMEM.
const SCRYPT_MAX_MEMORY = 32 * 1024 * 1024;
// workerd's scrypt rejects N * r * p above 2^20 ("cost exceeds maximum"), so a larger value is refused before
// computing. 1.6 times the work of the default parameters.
const SCRYPT_MAX_WORK = 2 ** 20;
const SCRYPT_MAX_SALT_BYTES = 64;

// The algorithm of new password hashes. Stored hashes are verified by their own format.
export type PasswordHashConfig = { algorithm: "scrypt" } | { algorithm: "pbkdf2"; iterations: number };

const encoder = new TextEncoder();

// Workers-specific API, declared here as in @cloudflare/workers-types so that the client tsconfig,
// which also loads the DOM lib through AppType, accepts it.
declare global {
  interface SubtleCrypto {
    timingSafeEqual(a: ArrayBuffer | ArrayBufferView, b: ArrayBuffer | ArrayBufferView): boolean;
  }
}

// Used when the user does not exist or has no password, so that the response time does not reveal it.
// A 16-byte salt and a 32-byte hash of zeros in base64url.
function dummyHash(config: PasswordHashConfig): string {
  const saltAndHash = `${"A".repeat(22)}$${"A".repeat(43)}`;
  if (config.algorithm === "scrypt") return `${SCRYPT_ALGORITHM}$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${saltAndHash}`;
  return `${PBKDF2_ALGORITHM}$${config.iterations}$${saltAndHash}`;
}

function assertIterations(iterations: number): void {
  if (!Number.isInteger(iterations) || iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
    throw new RangeError(
      `PBKDF2 iterations must be an integer from ${MIN_PBKDF2_ITERATIONS} to ${MAX_PBKDF2_ITERATIONS}`,
    );
  }
}

async function derivePbkdf2(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, HASH_BYTES * 8);
}

// The native scrypt of node:crypto. Exported for the tests only (not from the package entry point).
export function deriveScrypt(
  password: string,
  salt: Uint8Array,
  n: number,
  r: number,
  p: number,
  length = HASH_BYTES,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    nodeCrypto.scrypt(encoder.encode(password), salt, length, { N: n, r, p, maxmem: SCRYPT_MAXMEM }, (error, key) => {
      if (error) reject(error);
      else resolve(new Uint8Array(key.buffer, key.byteOffset, key.byteLength));
    });
  });
}

// Throws a RangeError for a PBKDF2 config outside MIN_PBKDF2_ITERATIONS..MAX_PBKDF2_ITERATIONS.
export async function hashPassword(password: string, config: PasswordHashConfig): Promise<string> {
  if (config.algorithm === "pbkdf2") {
    assertIterations(config.iterations);
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const hash = await derivePbkdf2(password, salt, config.iterations);
    return `${PBKDF2_ALGORITHM}$${config.iterations}$${base64UrlEncode(salt)}$${base64UrlEncode(new Uint8Array(hash))}`;
  }
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await deriveScrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P);
  return `${SCRYPT_ALGORITHM}$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${base64UrlEncode(salt)}$${base64UrlEncode(hash)}`;
}

// Dispatches on the format of the stored hash. A malformed value is false without computing; never throws.
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  if (stored.startsWith(`${SCRYPT_ALGORITHM}$`)) return verifyScrypt(password, stored);
  if (stored.startsWith(`${PBKDF2_ALGORITHM}$`)) return verifyPbkdf2(password, stored);
  return false;
}

async function verifyPbkdf2(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4) return false;
  const [algorithm, iterationsText, saltText, hashText] = parts as [string, string, string, string];
  if (algorithm !== PBKDF2_ALGORITHM) return false;
  if (!/^[0-9]{1,6}$/.test(iterationsText)) return false;
  const iterations = Number(iterationsText);
  if (iterations < 1 || iterations > MAX_PBKDF2_ITERATIONS) return false;
  const salt = base64UrlDecode(saltText);
  const expected = base64UrlDecode(hashText);
  if (salt === null || salt.length === 0 || expected === null || expected.length !== HASH_BYTES) return false;
  let actual: ArrayBuffer;
  try {
    actual = await derivePbkdf2(password, salt, iterations);
  } catch (error) {
    logComputationError(error);
    return false;
  }
  return crypto.subtle.timingSafeEqual(actual, expected);
}

async function verifyScrypt(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6) return false;
  const [algorithm, nText, rText, pText, saltText, hashText] = parts as [string, string, string, string, string, string];
  if (algorithm !== SCRYPT_ALGORITHM) return false;
  const n = parseScryptParameter(nText);
  const r = parseScryptParameter(rText);
  const p = parseScryptParameter(pText);
  if (n === null || r === null || p === null) return false;
  // A power of two (N is at most 2^16, so the bitwise test is exact).
  if (n < SCRYPT_MIN_N || n > SCRYPT_MAX_N || (n & (n - 1)) !== 0) return false;
  if (r > SCRYPT_MAX_R || p > SCRYPT_MAX_P) return false;
  if (128 * n * r > SCRYPT_MAX_MEMORY || n * r * p > SCRYPT_MAX_WORK) return false;
  const salt = base64UrlDecode(saltText);
  const expected = base64UrlDecode(hashText);
  if (salt === null || salt.length === 0 || salt.length > SCRYPT_MAX_SALT_BYTES) return false;
  if (expected === null || expected.length !== HASH_BYTES) return false;
  let actual: Uint8Array;
  try {
    actual = await deriveScrypt(password, salt, n, r, p);
  } catch (error) {
    logComputationError(error);
    return false;
  }
  return crypto.subtle.timingSafeEqual(actual, expected);
}

// 1 to 7 digits without a leading zero, or null.
function parseScryptParameter(text: string): number | null {
  return /^[1-9][0-9]{0,6}$/.test(text) ? Number(text) : null;
}

// Logs no password, hash or email. Not describeError from middleware.ts, which would be an import cycle.
function logComputationError(error: unknown): void {
  console.error(
    "password hash computation failed",
    error instanceof Error ? { name: error.name, message: error.message } : { type: typeof error },
  );
}

// Runs the configured algorithm, so the time still differs from users whose hash uses another algorithm or
// parameters. Throws a RangeError for a PBKDF2 config outside MIN_PBKDF2_ITERATIONS..MAX_PBKDF2_ITERATIONS.
export async function verifyDummyPassword(password: string, config: PasswordHashConfig): Promise<void> {
  if (config.algorithm === "pbkdf2") assertIterations(config.iterations);
  await verifyPassword(password, dummyHash(config));
}
