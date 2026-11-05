import { base64UrlDecode, base64UrlEncode } from "./tokens.js";

export const PBKDF2_ITERATIONS = 100000;
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
const DUMMY_HASH = `${ALGORITHM}$${PBKDF2_ITERATIONS}$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;

async function derive(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, HASH_BYTES * 8);
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await derive(password, salt, PBKDF2_ITERATIONS);
  return `${ALGORITHM}$${PBKDF2_ITERATIONS}$${base64UrlEncode(salt)}$${base64UrlEncode(new Uint8Array(hash))}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4) return false;
  const [algorithm, iterationsText, saltText, hashText] = parts as [string, string, string, string];
  if (algorithm !== ALGORITHM) return false;
  if (!/^[0-9]{1,6}$/.test(iterationsText)) return false;
  const iterations = Number(iterationsText);
  if (iterations < 1 || iterations > PBKDF2_ITERATIONS) return false;
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

export async function verifyDummyPassword(password: string): Promise<void> {
  await verifyPassword(password, DUMMY_HASH);
}
