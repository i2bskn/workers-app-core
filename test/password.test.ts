import nodeCrypto from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_PBKDF2_ITERATIONS,
  deriveScrypt,
  hashPassword,
  SCRYPT_N,
  SCRYPT_P,
  SCRYPT_R,
  verifyDummyPassword,
  verifyPassword,
  type PasswordHashConfig,
} from "../src/auth/password.js";
import { base64UrlDecode, base64UrlEncode } from "../src/auth/tokens.js";

afterEach(() => {
  vi.restoreAllMocks();
});

const pbkdf2 = (iterations: number): PasswordHashConfig => ({ algorithm: "pbkdf2", iterations });
const SCRYPT: PasswordHashConfig = { algorithm: "scrypt" };
const toHex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

describe("password hashing", () => {
  it("uses the documented format with 100000 iterations by default", async () => {
    const hash = await hashPassword("correct horse battery", pbkdf2(DEFAULT_PBKDF2_ITERATIONS));
    expect(DEFAULT_PBKDF2_ITERATIONS).toBe(100000);
    expect(hash).toMatch(/^pbkdf2_sha256\$100000\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/);
  });

  it.each([10000, 50000, 100000])("records %i iterations in the hash", async (iterations) => {
    const hash = await hashPassword("correct horse battery", pbkdf2(iterations));
    expect(hash).toMatch(new RegExp(`^pbkdf2_sha256\\$${iterations}\\$[A-Za-z0-9_-]{22}\\$[A-Za-z0-9_-]{43}$`));
  });

  it("verifies the correct password and rejects a wrong one", async () => {
    const hash = await hashPassword("correct horse battery", pbkdf2(DEFAULT_PBKDF2_ITERATIONS));
    expect(await verifyPassword("correct horse battery", hash)).toBe(true);
    expect(await verifyPassword("correct horse battery!", hash)).toBe(false);
  });

  it("verifies hashes created with different iterations", async () => {
    const lower = await hashPassword("correct horse battery", pbkdf2(50000));
    const higher = await hashPassword("correct horse battery", pbkdf2(100000));
    expect(await verifyPassword("correct horse battery", lower)).toBe(true);
    expect(await verifyPassword("correct horse battery", higher)).toBe(true);
    expect(await verifyPassword("correct horse battery!", lower)).toBe(false);
  });

  it.each([9999, 100001, 50000.5, Number.NaN])("throws for %s iterations", async (iterations) => {
    await expect(hashPassword("correct horse battery", pbkdf2(iterations))).rejects.toThrow(RangeError);
    await expect(verifyDummyPassword("correct horse battery", pbkdf2(iterations))).rejects.toThrow(RangeError);
  });

  it("uses a random salt", async () => {
    expect(await hashPassword("correct horse battery", pbkdf2(DEFAULT_PBKDF2_ITERATIONS)))
      .not.toBe(await hashPassword("correct horse battery", pbkdf2(DEFAULT_PBKDF2_ITERATIONS)));
    expect(await hashPassword("correct horse battery", SCRYPT))
      .not.toBe(await hashPassword("correct horse battery", SCRYPT));
  });

  it("returns false without throwing for malformed hashes", async () => {
    const valid = await hashPassword("correct horse battery", pbkdf2(DEFAULT_PBKDF2_ITERATIONS));
    const [, , salt, hash] = valid.split("$");
    const short = base64UrlEncode(new Uint8Array(16));
    const cases = [
      "",
      "garbage",
      `pbkdf2_sha512$100000$${salt}$${hash}`,
      `pbkdf2_sha256$100001$${salt}$${hash}`,
      `pbkdf2_sha256$0$${salt}$${hash}`,
      `pbkdf2_sha256$-1$${salt}$${hash}`,
      `pbkdf2_sha256$abc$${salt}$${hash}`,
      `pbkdf2_sha256$100000$${salt}$${short}`,
      `pbkdf2_sha256$100000$${salt}$!!!`,
      `pbkdf2_sha256$100000$$${hash}`,
      `${valid}$extra`,
    ];
    for (const stored of cases) {
      await expect(verifyPassword("correct horse battery", stored)).resolves.toBe(false);
    }
  });

  it("runs the dummy verification without throwing", async () => {
    await expect(verifyDummyPassword("whatever", pbkdf2(DEFAULT_PBKDF2_ITERATIONS))).resolves.toBeUndefined();
    await expect(verifyDummyPassword("whatever", SCRYPT)).resolves.toBeUndefined();
  });

  it.each([20000, 100000])("derives the dummy hash with %i iterations", async (iterations) => {
    const deriveBits = vi.spyOn(crypto.subtle, "deriveBits");
    const scrypt = vi.spyOn(nodeCrypto, "scrypt");
    await expect(verifyDummyPassword("whatever", pbkdf2(iterations))).resolves.toBeUndefined();
    expect(deriveBits).toHaveBeenCalledTimes(1);
    expect(deriveBits.mock.calls[0]?.[0]).toMatchObject({ name: "PBKDF2", iterations });
    expect(scrypt).not.toHaveBeenCalled();
  });
});

describe("scrypt password hashing", () => {
  it("uses the documented format and parameters", async () => {
    expect([SCRYPT_N, SCRYPT_R, SCRYPT_P]).toEqual([8192, 8, 10]);
    const hash = await hashPassword("correct horse battery", SCRYPT);
    expect(hash).toMatch(/^scrypt\$8192\$8\$10\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/);
    const [, , , , salt, key] = hash.split("$");
    expect(base64UrlDecode(salt ?? "")?.length).toBe(16);
    expect(base64UrlDecode(key ?? "")?.length).toBe(32);
  });

  it("verifies the correct password and rejects a wrong one", async () => {
    const hash = await hashPassword("correct horse battery", SCRYPT);
    expect(await verifyPassword("correct horse battery", hash)).toBe(true);
    expect(await verifyPassword("correct horse battery!", hash)).toBe(false);
  });

  it("calls scrypt with the fixed parameters and maxmem", async () => {
    const scrypt = vi.spyOn(nodeCrypto, "scrypt");
    await hashPassword("correct horse battery", SCRYPT);
    expect(scrypt).toHaveBeenCalledTimes(1);
    expect(scrypt.mock.calls[0]?.[2]).toBe(32);
    expect(scrypt.mock.calls[0]?.[3]).toEqual({ N: 8192, r: 8, p: 10, maxmem: 64 * 1024 * 1024 });
  });

  it("matches the RFC 7914 test vector", async () => {
    // RFC 7914, section 12: P="password", S="NaCl", N=1024, r=8, p=16, dkLen=64. A shorter output is its prefix.
    const salt = new TextEncoder().encode("NaCl");
    expect(toHex(await deriveScrypt("password", salt, 1024, 8, 16, 64))).toBe(
      "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162" +
        "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
    );
    expect(toHex(await deriveScrypt("password", salt, 1024, 8, 16))).toBe(
      "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162",
    );
  });

  it("verifies a stored hash with other accepted parameters", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveScrypt("correct horse battery", salt, 1024, 8, 16);
    const stored = `scrypt$1024$8$16$${base64UrlEncode(salt)}$${base64UrlEncode(key)}`;
    expect(await verifyPassword("correct horse battery", stored)).toBe(true);
    expect(await verifyPassword("correct horse battery!", stored)).toBe(false);
  });

  it("returns false for malformed hashes without computing", async () => {
    const salt = base64UrlEncode(new Uint8Array(16));
    const key = base64UrlEncode(new Uint8Array(32));
    const scrypt = vi.spyOn(nodeCrypto, "scrypt");
    const cases = [
      "scrypt",
      "scrypt$",
      `scrypt$8192$8$${salt}$${key}`,
      `scrypt$8192$8$10$${salt}$${key}$extra`,
      `scrypt$3$8$10$${salt}$${key}`,
      `scrypt$512$8$10$${salt}$${key}`,
      `scrypt$12288$8$10$${salt}$${key}`,
      `scrypt$${2 ** 17}$8$10$${salt}$${key}`,
      `scrypt$${2 ** 20}$8$10$${salt}$${key}`,
      `scrypt$8192$0$10$${salt}$${key}`,
      `scrypt$8192$8$0$${salt}$${key}`,
      `scrypt$8192$17$1$${salt}$${key}`,
      `scrypt$1024$8$17$${salt}$${key}`,
      // N * r * p above 2^20, the limit of workerd's scrypt (1,114,112 > 1,048,576), and twice the default.
      `scrypt$8192$8$17$${salt}$${key}`,
      `scrypt$8192$10$16$${salt}$${key}`,
      `scrypt$16384$16$5$${salt}$${key}`,
      // 128 * N * r above 32 MiB.
      `scrypt$65536$8$1$${salt}$${key}`,
      `scrypt$08192$8$10$${salt}$${key}`,
      `scrypt$8192$08$10$${salt}$${key}`,
      `scrypt$8192$8$010$${salt}$${key}`,
      `scrypt$10000000$8$10$${salt}$${key}`,
      `scrypt$8192$00000008$10$${salt}$${key}`,
      `scrypt$-8192$8$10$${salt}$${key}`,
      `scrypt$8192.0$8$10$${salt}$${key}`,
      `scrypt$ 8192$8$10$${salt}$${key}`,
      `scrypt$8192$8$10$$${key}`,
      `scrypt$8192$8$10$!!!$${key}`,
      `scrypt$8192$8$10$${base64UrlEncode(new Uint8Array(65))}$${key}`,
      `scrypt$8192$8$10$${salt}$${base64UrlEncode(new Uint8Array(31))}`,
      `scrypt$8192$8$10$${salt}$${base64UrlEncode(new Uint8Array(33))}`,
      `scrypt$8192$8$10$${salt}$!!!`,
      `Scrypt$8192$8$10$${salt}$${key}`,
    ];
    for (const stored of cases) {
      await expect(verifyPassword("correct horse battery", stored), stored).resolves.toBe(false);
    }
    expect(scrypt).not.toHaveBeenCalled();
  });

  it("computes the hashes at the upper bounds", async () => {
    // N * r * p exactly 2^20, the limit of workerd's scrypt.
    for (const [n, r, p] of [[8192, 8, 16], [16384, 16, 4], [65536, 4, 4]] as const) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const key = await deriveScrypt("correct horse battery", salt, n, r, p);
      const stored = `scrypt$${n}$${r}$${p}$${base64UrlEncode(salt)}$${base64UrlEncode(key)}`;
      expect(await verifyPassword("correct horse battery", stored), stored).toBe(true);
    }
  });

  it("verifies a hash with 128 * N * r of exactly 32 MiB and a 64-byte salt", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(64));
    const key = await deriveScrypt("correct horse battery", salt, 65536, 4, 4);
    const stored = `scrypt$65536$4$4$${base64UrlEncode(salt)}$${base64UrlEncode(key)}`;
    expect(await verifyPassword("correct horse battery", stored)).toBe(true);
  });

  it("logs and returns false when scrypt fails", async () => {
    const hash = await hashPassword("correct horse battery", SCRYPT);
    vi.spyOn(nodeCrypto, "scrypt").mockImplementation(() => {
      throw new Error("scrypt exploded");
    });
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(verifyPassword("correct horse battery", hash)).resolves.toBe(false);
    expect(error).toHaveBeenCalledTimes(1);
    expect(error.mock.calls[0]).toEqual([
      "password hash computation failed",
      { name: "Error", message: "scrypt exploded" },
    ]);
    const logged = JSON.stringify(error.mock.calls);
    expect(logged).not.toContain("correct horse battery");
    for (const part of hash.split("$").slice(4)) expect(logged).not.toContain(part);
  });

  it("logs and returns false when PBKDF2 fails", async () => {
    const hash = await hashPassword("correct horse battery", pbkdf2(DEFAULT_PBKDF2_ITERATIONS));
    vi.spyOn(crypto.subtle, "deriveBits").mockRejectedValue("not an error");
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(verifyPassword("correct horse battery", hash)).resolves.toBe(false);
    expect(error.mock.calls).toEqual([["password hash computation failed", { type: "string" }]]);
  });

  it("throws when hashing fails", async () => {
    vi.spyOn(nodeCrypto, "scrypt").mockImplementation(() => {
      throw new Error("scrypt exploded");
    });
    await expect(hashPassword("correct horse battery", SCRYPT)).rejects.toThrow("scrypt exploded");
  });

  it("derives the dummy hash with scrypt", async () => {
    const scrypt = vi.spyOn(nodeCrypto, "scrypt");
    const deriveBits = vi.spyOn(crypto.subtle, "deriveBits");
    await expect(verifyDummyPassword("whatever", SCRYPT)).resolves.toBeUndefined();
    expect(scrypt).toHaveBeenCalledTimes(1);
    expect(scrypt.mock.calls[0]?.[3]).toMatchObject({ N: 8192, r: 8, p: 10 });
    expect(deriveBits).not.toHaveBeenCalled();
  });
});
