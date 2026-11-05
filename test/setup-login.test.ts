import { beforeEach, describe, expect, it } from "vitest";
import { countUsers, createInitialAdmin } from "../src/auth/users.js";
import { users } from "../src/db/schema.js";
import {
  createUser,
  db,
  oidcEnv,
  PASSWORD,
  resetDb,
  send,
  sessionCookies,
  setCookies,
} from "./helpers.js";

beforeEach(resetDb);

const setupForm = {
  email: "Admin@Example.com",
  name: "Admin",
  password: PASSWORD,
  password_confirm: PASSWORD,
};

describe("initial setup", () => {
  it("redirects the login page to setup when there are no users", async () => {
    const res = await send("/auth/login");
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/auth/setup");
  });

  it("creates the first admin and signs in", async () => {
    expect((await send("/auth/setup")).status).toBe(200);
    const res = await send("/auth/setup", { form: setupForm });
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/");
    sessionCookies(res);

    const all = await db.select().from(users).all();
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ email: "admin@example.com", name: "Admin", role: "admin" });
    expect(all[0]?.lastLoginAt).not.toBeNull();
  });

  it("returns 404 once a user exists", async () => {
    expect((await send("/auth/setup", { form: setupForm })).status).toBe(303);
    expect((await send("/auth/setup")).status).toBe(404);
    expect((await send("/auth/setup", { form: { ...setupForm, email: "other@example.com" } })).status).toBe(404);
    expect(await countUsers(db)).toBe(1);
  });

  it("creates only one admin for concurrent requests", async () => {
    const results = await Promise.all([
      send("/auth/setup", { form: setupForm }),
      send("/auth/setup", { form: { ...setupForm, email: "second@example.com" } }),
    ]);
    const statuses = results.map((r) => r.status).sort();
    expect(statuses[0]).toBe(303);
    expect([404, 409]).toContain(statuses[1]);
    const admins = await db.select().from(users).all();
    expect(admins).toHaveLength(1);
    expect(admins[0]?.role).toBe("admin");
  });

  it("creates the admin in one statement only when there are no users", async () => {
    const params = { email: "a@example.com", name: null, passwordHash: "x", now: Date.now() };
    const created = await createInitialAdmin(db, params);
    expect(created).toMatchObject({ role: "admin" });
    expect(await createInitialAdmin(db, { ...params, email: "b@example.com" })).toBeNull();
  });

  it("re-renders the form with 400 on invalid input without echoing the password", async () => {
    const res = await send("/auth/setup", { form: { ...setupForm, password_confirm: "different password" } });
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain('value="Admin@Example.com"');
    expect(html).not.toContain(PASSWORD);
    expect((await send("/auth/setup", { form: { ...setupForm, email: "bad" } })).status).toBe(400);
    expect((await send("/auth/setup", { form: { ...setupForm, password: "short", password_confirm: "short" } })).status).toBe(400);
    expect(await countUsers(db)).toBe(0);
  });
});

describe("password login", () => {
  beforeEach(async () => {
    await createUser({ email: "alice@example.com", role: "admin" });
  });

  it("sets two cookies and redirects with 303 on success", async () => {
    const res = await send("/auth/login", {
      form: { email: " Alice@Example.com ", password: PASSWORD, next: "/wiki?x=1#top" },
    });
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/wiki?x=1#top");
    const cookies = setCookies(res);
    expect(Object.keys(cookies).sort()).toEqual(["__Host-testapp_at", "__Host-testapp_rt"]);
    for (const cookie of Object.values(cookies)) {
      expect(cookie.raw).toMatch(/HttpOnly/);
      expect(cookie.raw).toMatch(/Secure/);
      expect(cookie.raw).toMatch(/SameSite=Lax/);
      expect(cookie.raw).toMatch(/Path=\//);
    }
    expect(cookies["__Host-testapp_at"]?.maxAge).toBe(15 * 60);
    expect(cookies["__Host-testapp_rt"]?.maxAge).toBe(30 * 24 * 60 * 60);
  });

  it("returns 401 for a wrong password", async () => {
    const res = await send("/auth/login", { form: { email: "alice@example.com", password: "wrong password!" } });
    expect(res.status).toBe(401);
    expect(await res.text()).toContain("メールアドレスまたはパスワードが違います");
    expect(res.headers.getSetCookie()).toHaveLength(0);
  });

  it("returns 401 for an unknown email", async () => {
    const res = await send("/auth/login", { form: { email: "nobody@example.com", password: PASSWORD } });
    expect(res.status).toBe(401);
    expect(await res.text()).toContain("メールアドレスまたはパスワードが違います");
  });

  it("returns 401 for a user without a password", async () => {
    await createUser({ email: "oidc@example.com", password: null });
    const res = await send("/auth/login", { form: { email: "oidc@example.com", password: PASSWORD } });
    expect(res.status).toBe(401);
  });

  it("replaces an external next with /", async () => {
    const res = await send("/auth/login", {
      form: { email: "alice@example.com", password: PASSWORD, next: "https://evil.example/" },
    });
    expect(res.headers.get("Location")).toBe("/");
  });

  it("shows the login form when signed out", async () => {
    const res = await send("/auth/login?next=/wiki");
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('name="next" value="/wiki"');
  });

  it("sets security headers on pages and API", async () => {
    const page = await send("/auth/login");
    expect(page.headers.get("Cache-Control")).toBe("no-store");
    expect(page.headers.get("Content-Security-Policy")).toBe("frame-ancestors 'none'");
    expect(page.headers.get("X-Content-Type-Options")).toBe("nosniff");
    const api = await send("/api/v1/me");
    expect(api.status).toBe(401);
    expect(api.headers.get("Cache-Control")).toBe("no-store");
  });

  it("returns 404 for the OIDC callback in password mode", async () => {
    expect((await send("/auth/oidc/callback?code=x&state=y")).status).toBe(404);
  });

  it("returns 500 for every request when the configuration is invalid", async () => {
    const res = await send("/auth/login", { env: { JWT_SECRET: "short" } });
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("short");
    expect((await send("/api/v1/me", { env: { AUTH_MODE: "ldap" } })).status).toBe(500);
    expect((await send("/", { env: { AUTH_MODE: "oidc" } })).status).toBe(500);
  });

  it("returns 500 when OIDC_REQUIRE_EMAIL_VERIFIED is invalid", async () => {
    const res = await send("/auth/login", { env: { ...oidcEnv, OIDC_REQUIRE_EMAIL_VERIFIED: "bogus" } });
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("bogus");
  });
});

describe("home", () => {
  // The static assets serve / (the SPA) in front of the Worker, so the Worker has no route for it.
  it("returns 404 for / in the Worker", async () => {
    expect((await send("/")).status).toBe(404);
  });
});
