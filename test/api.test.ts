import { eq } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { verifyPassword } from "../src/auth/password.js";
import { issueSession } from "../src/auth/sessions.js";
import { users, type UserRow } from "../src/db/schema.js";
import { env } from "cloudflare:workers";
import { core } from "./fixture/src/index.js";
import {
  createUser,
  db,
  login,
  OIDC_ORIGIN,
  oidcEnv,
  PASSWORD,
  resetDb,
  send,
  sessionCookies,
  type SessionCookies,
} from "./helpers.js";

const NEW_PASSWORD = "another long passphrase";

let admin: UserRow;
let member: UserRow;
let adminCookies: SessionCookies;
let memberCookies: SessionCookies;

beforeEach(async () => {
  await resetDb();
  admin = await createUser({ email: "admin@example.com", role: "admin", createdAt: 1000 });
  member = await createUser({ email: "member@example.com", role: "member", createdAt: 2000 });
  adminCookies = await login(admin.email);
  memberCookies = await login(member.email);
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function expectSignedOut(cookies: SessionCookies) {
  expect((await send("/api/v1/me", { cookies })).status).toBe(401);
  expect((await send("/auth/refresh", { method: "POST", cookies })).status).toBe(401);
}

describe("GET /api/v1/me", () => {
  it("returns the signed-in user", async () => {
    const res = await send("/api/v1/me", { cookies: memberCookies });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({
      id: member.id,
      email: "member@example.com",
      name: null,
      role: "member",
      created_at: 2000,
      last_login_at: expect.any(Number),
    });
  });

  it("returns 401 without or with a tampered token", async () => {
    expect((await send("/api/v1/me")).status).toBe(401);
    const tampered = `${memberCookies["__Host-testapp_at"]}x`;
    const res = await send("/api/v1/me", { cookies: { "__Host-testapp_at": tampered } });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: { code: "unauthorized", message: expect.any(String) } });
  });

  it("rejects tokens with a different audience or secret", async () => {
    const session = await issueSession(db, member.id, "password", Date.now());
    const wrongSecret = await core.signAccessToken(
      { sub: member.id, sid: session.sessionId },
      "another-secret-another-secret-another-secret",
      Date.now(),
    );
    expect((await send("/api/v1/me", { cookies: { "__Host-testapp_at": wrongSecret } })).status).toBe(401);
    const valid = await core.signAccessToken({ sub: member.id, sid: session.sessionId }, env.JWT_SECRET ?? "", Date.now());
    expect((await send("/api/v1/me", { cookies: { "__Host-testapp_at": valid } })).status).toBe(200);
  });
});

describe("POST /api/v1/me/password", () => {
  it("changes the password, revokes other sessions and issues a new one", async () => {
    const otherDevice = await login(member.email);
    const res = await send("/api/v1/me/password", {
      cookies: memberCookies,
      json: { current_password: PASSWORD, new_password: NEW_PASSWORD },
    });
    expect(res.status).toBe(204);
    const fresh = sessionCookies(res);

    await expectSignedOut(memberCookies);
    await expectSignedOut(otherDevice);
    expect((await send("/api/v1/me", { cookies: fresh })).status).toBe(200);
    expect((await send("/auth/refresh", { method: "POST", cookies: fresh })).status).toBe(204);

    const row = await db.select().from(users).where(eq(users.id, member.id)).get();
    expect(await verifyPassword(NEW_PASSWORD, row?.passwordHash ?? "")).toBe(true);
  });

  it("validates input", async () => {
    const cases: [unknown, string][] = [
      ["not json", "invalid_body"],
      [[1, 2], "invalid_body"],
      [{ new_password: NEW_PASSWORD }, "invalid_current_password"],
      [{ current_password: PASSWORD, new_password: "short" }, "invalid_new_password"],
      [{ current_password: "wrong password!!", new_password: NEW_PASSWORD }, "invalid_current_password"],
    ];
    for (const [json, code] of cases) {
      const res = await send("/api/v1/me/password", { cookies: memberCookies, json });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe(code);
    }
  });

  it("accepts the same password as the current one", async () => {
    const res = await send("/api/v1/me/password", {
      cookies: memberCookies,
      json: { current_password: PASSWORD, new_password: PASSWORD, unknown: true },
    });
    expect(res.status).toBe(204);
  });

  it("returns password_not_set for users without a password", async () => {
    const oidcUser = await createUser({ email: "oidc@example.com", password: null });
    const session = await issueSession(db, oidcUser.id, "password", Date.now());
    const at = await core.signAccessToken({ sub: oidcUser.id, sid: session.sessionId }, env.JWT_SECRET ?? "", Date.now());
    const res = await send("/api/v1/me/password", {
      cookies: { "__Host-testapp_at": at },
      json: { current_password: PASSWORD, new_password: NEW_PASSWORD },
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("password_not_set");
  });
});

describe("admin user API", () => {
  it("lists users in created_at order", async () => {
    const res = await send("/api/v1/users", { cookies: adminCookies });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { users: { email: string }[] };
    expect(body.users.map((u) => u.email)).toEqual(["admin@example.com", "member@example.com"]);
    expect(Object.keys(body.users[0] ?? {}).sort()).toEqual(
      ["created_at", "email", "id", "last_login_at", "name", "role"].sort(),
    );
  });

  it("tells the auth mode with the list", async () => {
    const res = await send("/api/v1/users", { cookies: adminCookies });
    expect(((await res.json()) as { auth_mode: string }).auth_mode).toBe("password");
  });

  it("returns 403 to members", async () => {
    const res = await send("/api/v1/users", { cookies: memberCookies });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("forbidden");
    expect((await send(`/api/v1/users/${admin.id}`, { method: "PATCH", cookies: memberCookies, json: { role: "member" } })).status).toBe(403);
  });

  it("creates users", async () => {
    const res = await send("/api/v1/users", {
      cookies: adminCookies,
      json: { email: " New@Example.com ", name: " New ", password: NEW_PASSWORD, role: "member" },
    });
    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({ email: "new@example.com", name: "New", role: "member", last_login_at: null });
    expect((await login("new@example.com", NEW_PASSWORD))["__Host-testapp_at"]).toBeTruthy();
  });

  it("returns 409 email_taken for duplicate emails", async () => {
    const res = await send("/api/v1/users", {
      cookies: adminCookies,
      json: { email: "MEMBER@example.com", password: NEW_PASSWORD, role: "member" },
    });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("email_taken");
  });

  it("validates user creation input", async () => {
    const base = { email: "x@example.com", password: NEW_PASSWORD, role: "member" };
    const cases: [unknown, string][] = [
      [{ ...base, email: "bad" }, "invalid_email"],
      [{ ...base, name: "a".repeat(101) }, "invalid_name"],
      [{ ...base, password: "short" }, "invalid_password"],
      [{ ...base, role: "owner" }, "invalid_role"],
      [{ email: "x@example.com", role: "member" }, "invalid_password"],
    ];
    for (const [json, code] of cases) {
      const res = await send("/api/v1/users", { cookies: adminCookies, json });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe(code);
    }
  });

  it("resets a password and revokes the user's sessions", async () => {
    const res = await send(`/api/v1/users/${member.id}/password`, {
      cookies: adminCookies,
      json: { password: NEW_PASSWORD },
    });
    expect(res.status).toBe(204);
    await expectSignedOut(memberCookies);
    expect((await send("/api/v1/me", { cookies: adminCookies })).status).toBe(200);
    await login(member.email, NEW_PASSWORD);
  });

  it("revokes the admin's own sessions when resetting their own password", async () => {
    const res = await send(`/api/v1/users/${admin.id}/password`, {
      cookies: adminCookies,
      json: { password: NEW_PASSWORD },
    });
    expect(res.status).toBe(204);
    await expectSignedOut(adminCookies);
  });

  it("revokes all sessions of a user", async () => {
    const otherDevice = await login(member.email);
    const res = await send(`/api/v1/users/${member.id}/revoke-sessions`, { method: "POST", cookies: adminCookies });
    expect(res.status).toBe(204);
    await expectSignedOut(memberCookies);
    await expectSignedOut(otherDevice);
  });

  it("returns 404 not_found for unknown users", async () => {
    for (const [path, method, json] of [
      ["/api/v1/users/nope", "PATCH", { role: "admin" }],
      ["/api/v1/users/nope/password", "POST", { password: NEW_PASSWORD }],
      ["/api/v1/users/nope/revoke-sessions", "POST", undefined],
    ] as const) {
      const res = await send(path, { method, cookies: adminCookies, json });
      expect(res.status).toBe(404);
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe("not_found");
    }
  });

  it("changes roles", async () => {
    const promote = await send(`/api/v1/users/${member.id}`, { method: "PATCH", cookies: adminCookies, json: { role: "admin" } });
    expect(promote.status).toBe(200);
    expect(await promote.json()).toMatchObject({ role: "admin" });
    const demote = await send(`/api/v1/users/${admin.id}`, { method: "PATCH", cookies: adminCookies, json: { role: "member" } });
    expect(demote.status).toBe(200);
    expect(await demote.json()).toMatchObject({ role: "member" });
    // Roles are read from the DB on every request.
    expect((await send("/api/v1/users", { cookies: adminCookies })).status).toBe(403);
  });

  it("returns 200 for the same role", async () => {
    const res = await send(`/api/v1/users/${member.id}`, { method: "PATCH", cookies: adminCookies, json: { role: "member" } });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ id: member.id, role: "member" });
  });

  it("returns 409 last_admin when demoting the last admin", async () => {
    const res = await send(`/api/v1/users/${admin.id}`, { method: "PATCH", cookies: adminCookies, json: { role: "member" } });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("last_admin");
    const row = await db.select().from(users).where(eq(users.id, admin.id)).get();
    expect(row?.role).toBe("admin");
  });

  it("returns 400 for an invalid role", async () => {
    const res = await send(`/api/v1/users/${member.id}`, { method: "PATCH", cookies: adminCookies, json: { role: "root" } });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("invalid_role");
  });
});

describe("middleware order", () => {
  async function oidcCookiesFor(user: UserRow): Promise<SessionCookies> {
    const now = Date.now();
    const session = await issueSession(db, user.id, "oidc", now);
    const at = await core.signAccessToken({ sub: user.id, sid: session.sessionId }, env.JWT_SECRET ?? "", now);
    return { "__Host-testapp_at": at, "__Host-testapp_rt": session.refreshToken };
  }

  it("returns 404 before 403 for a member calling a password-only admin API in oidc mode", async () => {
    const cookies = await oidcCookiesFor(member);
    const res = await send(`${OIDC_ORIGIN}/api/v1/users`, {
      env: oidcEnv,
      cookies,
      json: { email: "x@example.com", password: NEW_PASSWORD, role: "member" },
    });
    expect(res.status).toBe(404);
  });

  it("returns 404 for password-only endpoints in oidc mode", async () => {
    const cookies = await oidcCookiesFor(admin);
    const me = await send(`${OIDC_ORIGIN}/api/v1/me`, { env: oidcEnv, cookies });
    expect(me.status).toBe(200);
    const change = await send(`${OIDC_ORIGIN}/api/v1/me/password`, {
      env: oidcEnv,
      cookies,
      json: { current_password: PASSWORD, new_password: NEW_PASSWORD },
    });
    expect(change.status).toBe(404);
    expect((await send(`${OIDC_ORIGIN}/auth/setup`, { env: oidcEnv })).status).toBe(404);
    const loginRes = await send(`${OIDC_ORIGIN}/auth/login`, {
      env: oidcEnv,
      form: { email: admin.email, password: PASSWORD },
    });
    expect(loginRes.status).toBe(404);
  });

  it("returns 401 before 400 for invalid input without a session", async () => {
    expect((await send("/api/v1/users", { json: "not json" })).status).toBe(401);
  });
});

describe("sameOrigin", () => {
  it("rejects cross-origin POST with 403", async () => {
    const res = await send("/api/v1/me/password", {
      cookies: memberCookies,
      origin: "https://evil.example",
      json: { current_password: PASSWORD, new_password: NEW_PASSWORD },
    });
    expect(res.status).toBe(403);
    expect((await send("/auth/logout", { method: "POST", cookies: memberCookies, origin: "https://evil.example" })).status).toBe(403);
    expect((await send("/auth/login", { origin: "null", form: { email: member.email, password: PASSWORD } })).status).toBe(403);
    // The session is untouched.
    expect((await send("/api/v1/me", { cookies: memberCookies })).status).toBe(200);
  });

  it("rejects POST without Origin and Sec-Fetch-Site", async () => {
    const res = await send("/auth/refresh", { method: "POST", cookies: memberCookies, origin: null });
    expect(res.status).toBe(403);
    const cross = await send("/auth/refresh", {
      method: "POST",
      cookies: memberCookies,
      origin: null,
      headers: { "Sec-Fetch-Site": "cross-site" },
    });
    expect(cross.status).toBe(403);
  });

  it("accepts POST without Origin when Sec-Fetch-Site is same-origin", async () => {
    const res = await send("/auth/refresh", {
      method: "POST",
      cookies: memberCookies,
      origin: null,
      headers: { "Sec-Fetch-Site": "same-origin" },
    });
    expect(res.status).toBe(204);
  });
});
