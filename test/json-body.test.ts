import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "./fixture/src/index.js";
import { createUser, login, ORIGIN, resetDb, type SessionCookies } from "./helpers.js";

let adminCookies: SessionCookies;

beforeEach(async () => {
  await resetDb();
  const admin = await createUser({ email: "admin@example.com", role: "admin" });
  adminCookies = await login(admin.email);
});

// Sends a request without the Content-Type handling of send().
async function post(path: string, body: BodyInit | null, contentType: string | null): Promise<Response> {
  const headers = new Headers({
    Origin: ORIGIN,
    Cookie: Object.entries(adminCookies)
      .map(([k, v]) => `${k}=${v}`)
      .join("; "),
  });
  if (contentType !== null) headers.set("Content-Type", contentType);
  const request = new Request(new URL(path, ORIGIN), { method: "POST", headers, body, redirect: "manual" });
  return worker.fetch(request, env, createExecutionContext());
}

const newUser = { email: "new@example.com", password: "a long enough password", role: "member" };

describe("JSON body", () => {
  it("accepts a JSON object without Content-Type", async () => {
    const body = new TextEncoder().encode(JSON.stringify(newUser));
    const res = await post("/api/v1/users", body, null);
    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({ email: "new@example.com", name: null, role: "member" });
  });

  it("does not set Content-Type for a Uint8Array body", () => {
    const request = new Request(ORIGIN, { method: "POST", body: new TextEncoder().encode("{}") });
    expect(request.headers.get("Content-Type")).toBeNull();
  });

  it("accepts a JSON object sent as text/plain", async () => {
    const res = await post("/api/v1/users", JSON.stringify(newUser), "text/plain");
    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({ email: "new@example.com", name: null, role: "member" });
  });

  it("returns 400 invalid_body for an empty application/json body", async () => {
    const res = await post("/api/v1/users", "", "application/json");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: { code: "invalid_body", message: expect.any(String) } });
  });
});
