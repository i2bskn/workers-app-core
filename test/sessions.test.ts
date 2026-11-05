import { eq } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { issueSession, revokeFamilyQuery, rotateSession, rotationStatements } from "../src/auth/sessions.js";
import { hashToken } from "../src/auth/tokens.js";
import { clock } from "../src/clock.js";
import { sessions, type UserRow } from "../src/db/schema.js";
import { loadConfig } from "../src/config.js";
import { env } from "cloudflare:workers";
import {
  createUser,
  db,
  login,
  OIDC_ORIGIN,
  oidcEnv,
  resetDb,
  send,
  sessionCookies,
  setCookies,
  type SessionCookies,
} from "./helpers.js";

const T0 = Date.UTC(2026, 9, 1);
const DAY = 24 * 60 * 60 * 1000;

let alice: UserRow;

function setNow(now: number) {
  vi.spyOn(clock, "now").mockReturnValue(now);
}

function refresh(cookies: Partial<SessionCookies>, options: { url?: string; env?: Record<string, string> } = {}) {
  return send(options.url ?? "/auth/refresh", { method: "POST", cookies, env: options.env });
}

async function familyRows(rt: string) {
  const row = await db.select().from(sessions).where(eq(sessions.tokenHash, await hashToken(rt))).get();
  if (!row) throw new Error("session not found");
  return db.select().from(sessions).where(eq(sessions.familyId, row.familyId)).all();
}

function expectCleared(res: Response) {
  const cookies = setCookies(res);
  expect(cookies["__Host-testapp_at"]?.maxAge).toBe(0);
  expect(cookies["__Host-testapp_rt"]?.maxAge).toBe(0);
}

beforeEach(async () => {
  await resetDb();
  alice = await createUser({ email: "alice@example.com", role: "admin" });
  setNow(T0);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("refresh", () => {
  it("rotates the tokens", async () => {
    const before = await login(alice.email);
    setNow(T0 + 1000);
    const res = await refresh(before);
    expect(res.status).toBe(204);
    const after = sessionCookies(res);
    expect(after["__Host-testapp_rt"]).not.toBe(before["__Host-testapp_rt"]);
    expect(after["__Host-testapp_at"]).not.toBe(before["__Host-testapp_at"]);
    expect(setCookies(res)["__Host-testapp_rt"]?.maxAge).toBe((30 * DAY - 1000) / 1000);

    const rows = await familyRows(after["__Host-testapp_rt"]);
    expect(rows).toHaveLength(2);
    const old = rows.find((r) => r.rotatedAt !== null);
    const current = rows.find((r) => r.rotatedAt === null);
    expect(old?.rotatedTo).toBe(current?.id);
    expect(current?.familyExpiresAt).toBe(T0 + 30 * DAY);

    expect((await send("/api/v1/me", { cookies: after })).status).toBe(200);
  });

  it("revokes the family when a used token is reused after 10 seconds", async () => {
    const first = await login(alice.email);
    setNow(T0 + 1000);
    const second = sessionCookies(await refresh(first));

    setNow(T0 + 1000 + 10_001);
    const res = await refresh(first);
    expect(res.status).toBe(401);
    expectCleared(res);
    const rows = await familyRows(second["__Host-testapp_rt"]);
    expect(rows.every((r) => r.revokedAt !== null)).toBe(true);

    expect((await refresh(second)).status).toBe(401);
    expect((await send("/api/v1/me", { cookies: second })).status).toBe(401);
  });

  it("does not revoke or clear cookies when a used token is reused within 10 seconds", async () => {
    const first = await login(alice.email);
    setNow(T0 + 1000);
    const second = sessionCookies(await refresh(first));

    setNow(T0 + 1000 + 10_000);
    const res = await refresh(first);
    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie()).toHaveLength(0);
    const rows = await familyRows(second["__Host-testapp_rt"]);
    expect(rows.every((r) => r.revokedAt === null)).toBe(true);

    expect((await refresh(second)).status).toBe(204);
  });

  it("fails after the absolute expiry and does not extend it", async () => {
    let cookies = await login(alice.email);
    setNow(T0 + 29 * DAY);
    const res = await refresh(cookies);
    expect(res.status).toBe(204);
    cookies = sessionCookies(res);
    expect(setCookies(res)["__Host-testapp_rt"]?.maxAge).toBe(DAY / 1000);

    setNow(T0 + 30 * DAY);
    const expired = await refresh(cookies);
    expect(expired.status).toBe(401);
    expectCleared(expired);
  });

  it("does not create a session when the family is revoked between UPDATE and INSERT", async () => {
    const issued = await issueSession(db, alice.id, "password", T0);
    const old = await db.select().from(sessions).where(eq(sessions.id, issued.sessionId)).get();
    if (!old) throw new Error("missing session");
    const newId = crypto.randomUUID();
    const { update, insert } = rotationStatements(db, { oldId: old.id, newId, newHash: "h", now: T0 + 1 });

    const updated = await update;
    expect(updated.meta.changes).toBe(1);
    await revokeFamilyQuery(db, old.familyId, T0 + 1).run();
    const inserted = await insert;
    expect(inserted.meta.changes).toBe(0);
    expect(await db.select().from(sessions).where(eq(sessions.id, newId)).get()).toBeUndefined();
  });

  it("succeeds only once for concurrent rotations at the same time", async () => {
    const cookies = await login(alice.email);
    setNow(T0 + 1000);
    const results = await Promise.all([refresh(cookies), refresh(cookies), refresh(cookies)]);
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([204, 401, 401]);
    for (const res of results.filter((r) => r.status === 401)) {
      expect(res.headers.getSetCookie()).toHaveLength(0);
    }
    const rows = await familyRows(cookies["__Host-testapp_rt"]);
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.revokedAt === null)).toBe(true);
  });

  it("succeeds only once when rotateSession runs twice with the same time", async () => {
    const config = loadConfig(env);
    if (!config.ok) throw new Error("invalid config");
    const issued = await issueSession(db, alice.id, "password", T0);
    const results = await Promise.all([
      rotateSession(db, config.config, issued.refreshToken, T0 + 1),
      rotateSession(db, config.config, issued.refreshToken, T0 + 1),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.find((r) => !r.ok)).toEqual({ ok: false, clearCookies: false });
  });

  it("returns 401 without a refresh cookie", async () => {
    expect((await refresh({})).status).toBe(401);
  });
});

describe("auth mode switch", () => {
  it("revokes password sessions after switching to oidc", async () => {
    const cookies = await login(alice.email);
    const res = await refresh(cookies, { url: `${OIDC_ORIGIN}/auth/refresh`, env: oidcEnv as Record<string, string> });
    expect(res.status).toBe(401);
    expectCleared(res);
    const rows = await familyRows(cookies["__Host-testapp_rt"]);
    expect(rows.every((r) => r.revokedAt !== null)).toBe(true);
    // Switching back does not revive it.
    expect((await refresh(cookies)).status).toBe(401);
  });

  it("revokes oidc sessions after switching to password", async () => {
    const issued = await issueSession(db, alice.id, "oidc", T0);
    const res = await refresh({ "__Host-testapp_rt": issued.refreshToken });
    expect(res.status).toBe(401);
    const rows = await familyRows(issued.refreshToken);
    expect(rows.every((r) => r.revokedAt !== null)).toBe(true);
  });

  it("revokes oidc sessions of users removed from the allowlist", async () => {
    const issued = await issueSession(db, alice.id, "oidc", T0);
    const res = await refresh(
      { "__Host-testapp_rt": issued.refreshToken },
      { url: `${OIDC_ORIGIN}/auth/refresh`, env: { ...(oidcEnv as Record<string, string>), ALLOWED_EMAILS: "other.com" } },
    );
    expect(res.status).toBe(401);
    const rows = await familyRows(issued.refreshToken);
    expect(rows.every((r) => r.revokedAt !== null)).toBe(true);
  });

  it("revokes oidc sessions when ALLOWED_EMAILS becomes empty", async () => {
    const issued = await issueSession(db, alice.id, "oidc", T0);
    const url = `${OIDC_ORIGIN}/auth/refresh`;
    // Allowed by the default allowlist of the tests.
    const allowed = await refresh({ "__Host-testapp_rt": issued.refreshToken }, { url, env: oidcEnv as Record<string, string> });
    expect(allowed.status).toBe(204);
    const cookies = sessionCookies(allowed);

    const res = await refresh(cookies, { url, env: { ...(oidcEnv as Record<string, string>), ALLOWED_EMAILS: "" } });
    expect(res.status).toBe(401);
    expectCleared(res);
    const rows = await familyRows(cookies["__Host-testapp_rt"]);
    expect(rows.every((r) => r.revokedAt !== null)).toBe(true);
  });

  it("uses a 24 hour absolute expiry for oidc sessions", async () => {
    const issued = await issueSession(db, alice.id, "oidc", T0);
    expect(issued.familyExpiresAt).toBe(T0 + DAY);
  });
});

describe("logout", () => {
  it("revokes the session so neither the refresh token nor the access token works", async () => {
    const cookies = await login(alice.email);
    const res = await send("/auth/logout", { method: "POST", cookies });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("ログアウトしました");
    expectCleared(res);

    expect((await refresh(cookies)).status).toBe(401);
    expect((await send("/api/v1/me", { cookies })).status).toBe(401);
  });

  it("finds the session from an expired access token when there is no refresh cookie", async () => {
    const cookies = await login(alice.email);
    setNow(T0 + 16 * 60 * 1000);
    const res = await send("/auth/logout", {
      method: "POST",
      cookies: { "__Host-testapp_at": cookies["__Host-testapp_at"] },
    });
    expect(res.status).toBe(200);
    expect((await refresh(cookies)).status).toBe(401);
  });

  it("returns the same page without a session", async () => {
    const res = await send("/auth/logout", { method: "POST" });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("ログアウトしました");
  });
});

describe("GET /auth/login", () => {
  it("rotates and redirects to next with a valid refresh cookie", async () => {
    const cookies = await login(alice.email);
    setNow(T0 + 1000);
    const res = await send("/auth/login?next=/wiki", { cookies });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/wiki");
    sessionCookies(res);
  });

  it("returns 204 for prefetch requests without rotating", async () => {
    const cookies = await login(alice.email);
    const prefetchHeaders: Record<string, string>[] = [
      { "Sec-Purpose": "prefetch" },
      { Purpose: "prefetch" },
      { "Sec-Purpose": "prefetch;prerender" },
    ];
    for (const headers of prefetchHeaders) {
      const res = await send("/auth/login?next=/wiki", { cookies, headers });
      expect(res.status).toBe(204);
      expect(res.headers.getSetCookie()).toHaveLength(0);
    }
    const rows = await familyRows(cookies["__Host-testapp_rt"]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.rotatedAt).toBeNull();
  });

  it("returns 204 for HEAD requests without rotating", async () => {
    const cookies = await login(alice.email);
    const res = await send("/auth/login?next=/wiki", { cookies, method: "HEAD" });
    expect(res.status).toBe(204);
    expect(res.headers.getSetCookie()).toHaveLength(0);
    const rows = await familyRows(cookies["__Host-testapp_rt"]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.rotatedAt).toBeNull();
  });

  it("clears cookies and shows the form when the refresh token is invalid", async () => {
    const res = await send("/auth/login", { cookies: { "__Host-testapp_rt": "unknown" } });
    expect(res.status).toBe(200);
    expectCleared(res);
  });
});
