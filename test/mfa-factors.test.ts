import { describe, expect, it } from "vitest";
import {
  createRecoveryCodes,
  decryptTotpSecret,
  encryptTotpSecret,
  generateTotpSecret,
  hashRecoveryCode,
  verifyTotp,
} from "../src/auth/mfa-factors.js";
import {
  verifyWebauthnAuthentication,
  verifyWebauthnRegistration,
  webauthnAuthenticationOptions,
  webauthnRegistrationOptions,
} from "../src/auth/webauthn.js";
import { base64UrlDecode, base64UrlEncode } from "../src/auth/tokens.js";
import { createTestAuthenticator } from "./fixture/webauthn.js";

describe("MFA factors", () => {
  it("matches the six-digit suffix of the RFC 6238 SHA1 test vectors and permits one adjacent time step", async () => {
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    for (const [seconds, code] of [[59, "287082"], [1111111109, "081804"], [1234567890, "005924"]] as const) {
      const step = Math.floor(seconds / 30);
      expect(await verifyTotp(secret, code, seconds * 1000)).toBe(step);
      expect(await verifyTotp(secret, code, (seconds + 30) * 1000)).toBe(step);
      expect(await verifyTotp(secret, code, (seconds + 60) * 1000)).toBeNull();
    }
    expect(await verifyTotp(secret, "081804 ", 1111111109_000)).toBeNull();
  });

  it("encrypts each secret with a fresh nonce and binds it to its user", async () => {
    const secret = generateTotpSecret();
    const key = btoa("12345678901234567890123456789012");
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    const encrypted = await encryptTotpSecret(secret, key, "userA");
    expect(await encryptTotpSecret(secret, key, "userA")).not.toBe(encrypted);
    expect(await decryptTotpSecret(encrypted, key, "userA")).toBe(secret);
    await expect(decryptTotpSecret(encrypted, key, "userB")).rejects.toThrow();
    await expect(decryptTotpSecret(encrypted, btoa("00000000000000000000000000000000"), "userA")).rejects.toThrow();
  });

  it("generates independent display codes and stores only their normalized hashes", async () => {
    const { codes, hashes } = await createRecoveryCodes();
    expect(new Set(codes).size).toBe(8);
    expect(codes[0]).toMatch(/^(?:[A-Z2-7]{4}-){5}[A-Z2-7]{4}$/);
    expect(hashes[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(await hashRecoveryCode(codes[0]!.toLowerCase().replaceAll("-", ""))).toBe(hashes[0]);
  });

  it("registers a credential and verifies its real signature against the configured RP and challenge", async () => {
    const origin = "https://app.test";
    const authenticator = await createTestAuthenticator(origin);
    const options = await webauthnRegistrationOptions(origin, "test", { id: "user", email: "a@example.com" }, []);
    const reply = await authenticator.register(options.challenge);
    expect(await verifyWebauthnRegistration(origin, "wrong", reply)).toBeNull();
    const credential = await verifyWebauthnRegistration(origin, options.challenge, reply);
    expect(credential).not.toBeNull();
    const request = await webauthnAuthenticationOptions(origin, [credential!]);
    const assertion = await authenticator.authenticate(request.challenge);
    expect(await verifyWebauthnAuthentication(origin, request.challenge, assertion, credential!)).toBe(1);
    expect(await verifyWebauthnAuthentication("https://other.test", request.challenge, assertion, credential!)).toBeNull();
    expect(await verifyWebauthnAuthentication(origin, request.challenge, assertion, { ...credential!, counter: 1 })).toBeNull();
    const signature = base64UrlDecode(assertion.response.signature)!;
    signature[0] = signature[0]! ^ 1;
    assertion.response.signature = base64UrlEncode(signature);
    expect(await verifyWebauthnAuthentication(origin, request.challenge, assertion, credential!)).toBeNull();
  });
});
