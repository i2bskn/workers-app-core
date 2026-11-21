import { base64UrlDecode, base64UrlEncode, hashToken } from "./tokens.js";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const TOTP_STEP_MS = 30_000;
const encoder = new TextEncoder();

function encodeBase32(bytes: Uint8Array): string {
  let bits = 0;
  let buffer = 0;
  let output = "";
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32[(buffer >>> bits) & 31];
    }
  }
  if (bits > 0) output += BASE32[(buffer << (5 - bits)) & 31];
  return output;
}

function decodeBase32(secret: string): Uint8Array<ArrayBuffer> {
  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const char of secret) {
    const digit = BASE32.indexOf(char);
    if (digit < 0) throw new Error("Invalid TOTP secret");
    buffer = (buffer << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 255);
    }
  }
  return new Uint8Array(bytes);
}

export function generateTotpSecret(): string {
  return encodeBase32(crypto.getRandomValues(new Uint8Array(20)));
}

async function totpEncryptionKey(encodedKey: string): Promise<CryptoKey> {
  const bytes = Uint8Array.from(atob(encodedKey), (char) => char.charCodeAt(0));
  if (bytes.length !== 32) throw new Error("Invalid TOTP encryption key");
  return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptTotpSecret(secret: string, key: string, userId: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(userId) },
    await totpEncryptionKey(key),
    encoder.encode(secret),
  );
  return base64UrlEncode(iv) + "." + base64UrlEncode(new Uint8Array(data));
}

export async function decryptTotpSecret(ciphertext: string, key: string, userId: string): Promise<string> {
  const parts = ciphertext.split(".");
  const iv = base64UrlDecode(parts[0] ?? "");
  const data = base64UrlDecode(parts[1] ?? "");
  if (parts.length !== 2 || iv?.length !== 12 || !data) throw new Error("Invalid encrypted TOTP secret");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(userId) },
    await totpEncryptionKey(key),
    data,
  );
  return new TextDecoder().decode(plain);
}

// Return the time step so the caller can atomically reject reuse, even across pending sign-ins.
export async function verifyTotp(secret: string, code: string, now: number): Promise<number | null> {
  if (!/^\d{6}$/.test(code)) return null;
  const key = await crypto.subtle.importKey("raw", decodeBase32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const currentStep = Math.floor(now / TOTP_STEP_MS);
  let match: number | null = null;
  for (let step = Math.max(0, currentStep - 1); step <= currentStep + 1; step++) {
    const counter = new ArrayBuffer(8);
    new DataView(counter).setBigUint64(0, BigInt(step));
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
    const offset = mac[mac.length - 1]! & 15;
    const truncated = new DataView(mac.buffer).getUint32(offset) & 0x7fffffff;
    if (truncated % 1_000_000 === Number(code)) match = step;
  }
  return match;
}

export function hashRecoveryCode(code: string): Promise<string> {
  return hashToken(code.trim().toUpperCase().replace(/-/g, ""));
}

export async function createRecoveryCodes(): Promise<{ codes: string[]; hashes: string[] }> {
  const codes = Array.from({ length: 8 }, () => {
    const random = encodeBase32(crypto.getRandomValues(new Uint8Array(15)));
    return random.match(/.{4}/g)!.join("-");
  });
  return { codes, hashes: await Promise.all(codes.map(hashRecoveryCode)) };
}
