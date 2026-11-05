import { describe, expect, it } from "vitest";
import { hashPassword, PBKDF2_ITERATIONS, verifyDummyPassword, verifyPassword } from "../src/auth/password.js";
import { base64UrlEncode } from "../src/auth/tokens.js";

describe("password hashing", () => {
  it("uses the documented format with 100000 iterations", async () => {
    const hash = await hashPassword("correct horse battery");
    expect(PBKDF2_ITERATIONS).toBe(100000);
    expect(hash).toMatch(/^pbkdf2_sha256\$100000\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/);
  });

  it("verifies the correct password and rejects a wrong one", async () => {
    const hash = await hashPassword("correct horse battery");
    expect(await verifyPassword("correct horse battery", hash)).toBe(true);
    expect(await verifyPassword("correct horse battery!", hash)).toBe(false);
  });

  it("uses a random salt", async () => {
    expect(await hashPassword("correct horse battery")).not.toBe(await hashPassword("correct horse battery"));
  });

  it("returns false without throwing for malformed hashes", async () => {
    const valid = await hashPassword("correct horse battery");
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
    await expect(verifyDummyPassword("whatever")).resolves.toBeUndefined();
  });
});
