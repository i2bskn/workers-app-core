import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_PBKDF2_ITERATIONS,
  hashPassword,
  verifyDummyPassword,
  verifyPassword,
} from "../src/auth/password.js";
import { base64UrlEncode } from "../src/auth/tokens.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("password hashing", () => {
  it("uses the documented format with 100000 iterations by default", async () => {
    const hash = await hashPassword("correct horse battery", DEFAULT_PBKDF2_ITERATIONS);
    expect(DEFAULT_PBKDF2_ITERATIONS).toBe(100000);
    expect(hash).toMatch(/^pbkdf2_sha256\$100000\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/);
  });

  it.each([10000, 50000, 100000])("records %i iterations in the hash", async (iterations) => {
    const hash = await hashPassword("correct horse battery", iterations);
    expect(hash).toMatch(new RegExp(`^pbkdf2_sha256\\$${iterations}\\$[A-Za-z0-9_-]{22}\\$[A-Za-z0-9_-]{43}$`));
  });

  it("verifies the correct password and rejects a wrong one", async () => {
    const hash = await hashPassword("correct horse battery", DEFAULT_PBKDF2_ITERATIONS);
    expect(await verifyPassword("correct horse battery", hash)).toBe(true);
    expect(await verifyPassword("correct horse battery!", hash)).toBe(false);
  });

  it("verifies hashes created with different iterations", async () => {
    const lower = await hashPassword("correct horse battery", 50000);
    const higher = await hashPassword("correct horse battery", 100000);
    expect(await verifyPassword("correct horse battery", lower)).toBe(true);
    expect(await verifyPassword("correct horse battery", higher)).toBe(true);
    expect(await verifyPassword("correct horse battery!", lower)).toBe(false);
  });

  it.each([9999, 100001, 50000.5, Number.NaN])("throws for %s iterations", async (iterations) => {
    await expect(hashPassword("correct horse battery", iterations)).rejects.toThrow(RangeError);
    await expect(verifyDummyPassword("correct horse battery", iterations)).rejects.toThrow(RangeError);
  });

  it("uses a random salt", async () => {
    expect(await hashPassword("correct horse battery", DEFAULT_PBKDF2_ITERATIONS))
      .not.toBe(await hashPassword("correct horse battery", DEFAULT_PBKDF2_ITERATIONS));
  });

  it("returns false without throwing for malformed hashes", async () => {
    const valid = await hashPassword("correct horse battery", DEFAULT_PBKDF2_ITERATIONS);
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
    await expect(verifyDummyPassword("whatever", DEFAULT_PBKDF2_ITERATIONS)).resolves.toBeUndefined();
  });

  it.each([20000, 100000])("derives the dummy hash with %i iterations", async (iterations) => {
    const deriveBits = vi.spyOn(crypto.subtle, "deriveBits");
    await expect(verifyDummyPassword("whatever", iterations)).resolves.toBeUndefined();
    expect(deriveBits).toHaveBeenCalledTimes(1);
    expect(deriveBits.mock.calls[0]?.[0]).toMatchObject({ name: "PBKDF2", iterations });
  });
});
