import { beforeEach, describe, expect, it, vi } from "vitest";
import { resetDb, send } from "./helpers.js";

beforeEach(resetDb);

function expectDefaultHeaders(res: Response): void {
  expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
  expect(res.headers.get("Referrer-Policy")).toBe("same-origin");
}

describe("default security headers of core.fetch", () => {
  it("adds them to the metadata served by OAuthProvider", async () => {
    const res = await send("/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    expectDefaultHeaders(res);
  });

  it("adds them to an invalid token request", async () => {
    const res = await send("/oauth/token", { form: { grant_type: "bogus" } });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    expectDefaultHeaders(res);
  });

  it("adds them to the API", async () => {
    const res = await send("/api/v1/me");
    expect(res.status).toBe(401);
    expectDefaultHeaders(res);
  });

  it("adds them to pages without repeating nosniff", async () => {
    const res = await send("/auth/login");
    expectDefaultHeaders(res);
    expect(res.headers.get("Content-Security-Policy")).toBe("frame-ancestors 'none'");
  });

  it("adds them to the 500 of an invalid configuration", async () => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await send("/auth/login", { env: { JWT_SECRET: "short" } });
    expect(res.status).toBe(500);
    expectDefaultHeaders(res);
    errorLog.mockRestore();
  });

  it("adds them on a plain http host that is not loopback", async () => {
    const me = await send("http://wiki.example.com/api/v1/me");
    expect(me.status).toBe(401);
    expectDefaultHeaders(me);
    const mcp = await send("http://wiki.example.com/mcp", { json: {} });
    expect(mcp.status).toBe(404);
    expectDefaultHeaders(mcp);
  });
});
