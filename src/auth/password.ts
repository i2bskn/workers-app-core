import { base64UrlDecode, base64UrlEncode } from "./tokens.js";

// Cloudflare Workers rejects PBKDF2 above 100,000 iterations in production (on every plan), while local workerd
// accepts it. Also the upper bound of the iterations accepted from a stored hash.
export const MAX_PBKDF2_ITERATIONS = 100000;
// Guards against a misconfiguration that would create very weak hashes.
export const MIN_PBKDF2_ITERATIONS = 10000;
export const DEFAULT_PBKDF2_ITERATIONS = 100000;
const ALGORITHM = "pbkdf2_sha256";
const SALT_BYTES = 16;
const HASH_BYTES = 32;

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
function dummyHash(iterations: number): string {
  return `${ALGORITHM}$${iterations}$${"A".repeat(22)}$${"A".repeat(43)}`;
}

function assertIterations(iterations: number): void {
  if (!Number.isInteger(iterations) || iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
    throw new RangeError(
      `PBKDF2 iterations must be an integer from ${MIN_PBKDF2_ITERATIONS} to ${MAX_PBKDF2_ITERATIONS}`,
    );
  }
}

async function derive(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, HASH_BYTES * 8);
}

// iterations is Config.passwordIterations. Throws a RangeError outside MIN_PBKDF2_ITERATIONS..MAX_PBKDF2_ITERATIONS.
export async function hashPassword(password: string, iterations: number): Promise<string> {
  assertIterations(iterations);
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await derive(password, salt, iterations);
  return `${ALGORITHM}$${iterations}$${base64UrlEncode(salt)}$${base64UrlEncode(new Uint8Array(hash))}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4) return false;
  const [algorithm, iterationsText, saltText, hashText] = parts as [string, string, string, string];
  if (algorithm !== ALGORITHM) return false;
  if (!/^[0-9]{1,6}$/.test(iterationsText)) return false;
  const iterations = Number(iterationsText);
  if (iterations < 1 || iterations > MAX_PBKDF2_ITERATIONS) return false;
  const salt = base64UrlDecode(saltText);
  const expected = base64UrlDecode(hashText);
  if (salt === null || salt.length === 0 || expected === null || expected.length !== HASH_BYTES) return false;
  try {
    const actual = await derive(password, salt, iterations);
    return crypto.subtle.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

// Runs with the configured iterations, so the time still differs from users whose hash uses another count.
export async function verifyDummyPassword(password: string, iterations: number): Promise<void> {
  assertIterations(iterations);
  await verifyPassword(password, dummyHash(iterations));
}
