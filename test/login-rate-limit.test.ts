import { beforeEach, describe, expect, it, vi } from "vitest";
import type { LoginRateLimiter } from "../src/config.js";
import { createUser, oidcEnv, PASSWORD, resetDb, send, sessionCookies } from "./helpers.js";

beforeEach(async () => {
  await resetDb();
  await createUser({ email: "alice@example.com" });
});

// A fake Rate Limiting binding that records the keys it is called with.
function fakeLimiter(result: boolean | Error): LoginRateLimiter & { keys: string[] } {
  const keys: string[] = [];
  return {
    keys,
    async limit({ key }) {
      keys.push(key);
      if (result instanceof Error) throw result;
      return { success: result };
    },
  };
}

const login = (email: string, limiter?: LoginRateLimiter, password = PASSWORD) =>
  send("/auth/login", { form: { email, password }, env: limiter ? { LOGIN_RATE_LIMITER: limiter } : {} });

describe("POST /auth/login rate limit", () => {
  it("signs in without a limit when the binding is unset", async () => {
    const res = await login("alice@example.com");
    expect(res.status).toBe(303);
  });

  it("counts each attempt and signs in while within the limit", async () => {
    const limiter = fakeLimiter(true);
    const ok = await login("alice@example.com", limiter);
    expect(ok.status).toBe(303);
    sessionCookies(ok);
    expect((await login("alice@example.com", limiter, "wrong password!")).status).toBe(401);
    expect(limiter.keys).toHaveLength(2);
  });

  it("keys the limit by a hash of the normalized email address", async () => {
    const limiter = fakeLimiter(true);
    await login("User@Example.com", limiter);
    await login("user@example.com", limiter);
    const [first, second] = limiter.keys;
    expect(first).toMatch(/^login:[0-9a-f]{64}$/);
    expect(first).not.toContain("user");
    expect(first).not.toContain("example");
    expect(second).toBe(first);
  });

  it("returns the login page with 429 over the limit, even for the right password", async () => {
    const res = await login("alice@example.com", fakeLimiter(false));
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("60");
    expect(res.headers.getSetCookie()).toHaveLength(0);
    const html = await res.text();
    expect(html).toContain("ログインの試行が多すぎます");
    expect(html).toContain('value="alice@example.com"');
  });

  it("returns 429 for an unknown email over the limit without checking the password", async () => {
    const res = await login("nobody@example.com", fakeLimiter(false));
    expect(res.status).toBe(429);
    expect(await res.text()).toContain("ログインの試行が多すぎます");
  });

  it("signs in when the binding fails", async () => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await login("alice@example.com", fakeLimiter(new Error("unavailable")));
    expect(res.status).toBe(303);
    expect(errorLog).toHaveBeenCalledWith("login rate limit failed", expect.objectContaining({ message: "unavailable" }));
    errorLog.mockRestore();
  });

  it("does not count an invalid or empty email", async () => {
    const limiter = fakeLimiter(false);
    expect((await login("not an email", limiter)).status).toBe(401);
    expect((await login("", limiter)).status).toBe(401);
    expect(limiter.keys).toHaveLength(0);
  });

  it("does not count in oidc mode", async () => {
    const limiter = fakeLimiter(false);
    const res = await send("https://wiki.example.com/auth/login", {
      form: { email: "alice@example.com", password: PASSWORD },
      env: { ...oidcEnv, LOGIN_RATE_LIMITER: limiter },
    });
    expect(res.status).toBe(404);
    expect(limiter.keys).toHaveLength(0);
  });
});
