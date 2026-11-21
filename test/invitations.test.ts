import { eq } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { env } from "cloudflare:workers";
import { INVITATION_TTL_MS } from "../src/auth/invitations.js";
import { verifyPassword } from "../src/auth/password.js";
import { hashToken } from "../src/auth/tokens.js";
import { clock } from "../src/clock.js";
import { users, type UserRow } from "../src/db/schema.js";
import { hooks } from "./fixture/src/index.js";
import {
  AT,
  createUser,
  db,
  login,
  OIDC_ORIGIN,
  oidcEnv,
  ORIGIN,
  PASSWORD,
  resetDb,
  RT,
  send,
  sessionCookies,
  setCookies,
  type SessionCookies,
} from "./helpers.js";

const NEW_PASSWORD = "invited user passphrase";
const INVALID = "招待リンクが無効か、有効期限が切れています。管理者に再発行を依頼してください。";

let admin: UserRow;
let adminCookies: SessionCookies;

beforeEach(async () => {
  await resetDb();
  admin = await createUser({ email: "admin@example.com", role: "admin" });
  adminCookies = await login(admin.email);
});

afterEach(() => {
  vi.restoreAllMocks();
});

type Created = { id: string; status: string; invitation: { url: string; expires_at: number } | null };

async function invite(email = "invited@example.com", options: { env?: Record<string, string>; role?: string } = {}) {
  const res = await send("/api/v1/users", {
    cookies: adminCookies,
    env: options.env,
    json: { email, name: "Invited", role: options.role ?? "member" },
  });
  expect(res.status).toBe(201);
  const body = (await res.json()) as Created;
  if (!body.invitation) throw new Error("invitation missing");
  return { ...body, invitation: body.invitation, token: new URL(body.invitation.url).searchParams.get("token") ?? "" };
}

function openLink(token: string, options: { env?: Record<string, string>; headers?: Record<string, string>; method?: string } = {}) {
  return send(`/auth/invite?token=${encodeURIComponent(token)}`, options);
}

function accept(token: string, options: { env?: Record<string, string>; password?: string; confirm?: string } = {}) {
  const password = options.password ?? NEW_PASSWORD;
  return send("/auth/invite", {
    env: options.env,
    form: { token, password, password_confirm: options.confirm ?? password },
  });
}

async function expectInvalid(res: Response) {
  expect(res.status).toBe(400);
  expect(await res.text()).toContain(INVALID);
}

async function invitationRows() {
  return (await env.DB.prepare("SELECT * FROM user_invitations").all<Record<string, unknown>>()).results;
}

async function readUser(id: string) {
  return db.select().from(users).where(eq(users.id, id)).get();
}

describe("POST /api/v1/users without a password (password mode)", () => {
  it("creates an invited user and returns the link once, storing only the token hash", async () => {
    const now = Date.UTC(2026, 10, 1);
    vi.spyOn(clock, "now").mockReturnValue(now);
    const created = await invite();
    expect(created).toMatchObject({ status: "invited", invitation: { expires_at: now + INVITATION_TTL_MS } });
    expect(INVITATION_TTL_MS).toBe(7 * 24 * 60 * 60 * 1000);
    expect(created.invitation.url).toBe(`${ORIGIN}/auth/invite?token=${created.token}`);
    expect(created.token.length).toBeGreaterThanOrEqual(40);

    expect((await readUser(created.id))?.passwordHash).toBeNull();
    const rows = await invitationRows();
    expect(rows).toEqual([
      { user_id: created.id, token_hash: await hashToken(created.token), expires_at: now + INVITATION_TTL_MS, created_at: now },
    ]);
    expect(JSON.stringify(rows)).not.toContain(created.token);

    const list = await send("/api/v1/users", { cookies: adminCookies });
    expect(JSON.stringify(await list.json())).not.toContain(created.token);
  });

  it("treats a null password as an invitation", async () => {
    const res = await send("/api/v1/users", {
      cookies: adminCookies,
      json: { email: "null@example.com", password: null, role: "member" },
    });
    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({ status: "invited", invitation: { url: expect.any(String) } });
  });

  it("uses APP_ORIGIN for the link when it is set", async () => {
    const created = await invite("invited@example.com", { env: { APP_ORIGIN: "https://canonical.example.com" } });
    expect(created.invitation.url).toBe(`https://canonical.example.com/auth/invite?token=${created.token}`);
  });

  it("inserts nothing when the email is taken", async () => {
    const res = await send("/api/v1/users", { cookies: adminCookies, json: { email: admin.email, role: "member" } });
    expect(res.status).toBe(409);
    expect(await invitationRows()).toEqual([]);
  });

  it("runs userCreatedStatements in the same batch", async () => {
    hooks.userCreatedStatements = (d1, userId) => [
      d1.prepare("INSERT INTO user_notes (user_id, note) SELECT ?1, 'invited' WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)").bind(userId),
    ];
    const created = await invite();
    const note = await env.DB.prepare("SELECT note FROM user_notes WHERE user_id = ?").bind(created.id).first("note");
    expect(note).toBe("invited");
  });
});

describe("GET /auth/invite", () => {
  it("shows the password form for a valid link without consuming it", async () => {
    const created = await invite();
    const res = await openLink(created.token);
    expect(res.status).toBe(200);
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const html = await res.text();
    expect(html).toContain("invited@example.com");
    expect(html).toContain('action="/auth/invite"');
    expect(html).toContain("パスワードを設定");
    expect(await invitationRows()).toHaveLength(1);
    // The link can be opened again.
    expect((await openLink(created.token)).status).toBe(200);
  });

  it("returns 400 for an unknown, missing or expired token", async () => {
    const now = Date.UTC(2026, 10, 1);
    const spy = vi.spyOn(clock, "now").mockReturnValue(now);
    const created = await invite();
    const unknown = await openLink("unknown");
    await expectInvalid(unknown);
    expect(unknown.headers.get("Referrer-Policy")).toBe("no-referrer");
    await expectInvalid(await send("/auth/invite"));
    spy.mockReturnValue(now + INVITATION_TTL_MS - 1);
    expect((await openLink(created.token)).status).toBe(200);
    spy.mockReturnValue(now + INVITATION_TTL_MS);
    await expectInvalid(await openLink(created.token));
    await expectInvalid(await accept(created.token));
    expect((await readUser(created.id))?.passwordHash).toBeNull();
  });

  it("answers HEAD and prefetches with 204", async () => {
    const created = await invite();
    expect((await openLink(created.token, { method: "HEAD" })).status).toBe(204);
    expect((await openLink(created.token, { headers: { "Sec-Purpose": "prefetch" } })).status).toBe(204);
    expect(await invitationRows()).toHaveLength(1);
  });

  it("returns 404 in oidc mode", async () => {
    expect((await send(`${OIDC_ORIGIN}/auth/invite?token=x`, { env: oidcEnv })).status).toBe(404);
    const post = await send(`${OIDC_ORIGIN}/auth/invite`, { env: oidcEnv, form: { token: "x", password: NEW_PASSWORD, password_confirm: NEW_PASSWORD } });
    expect(post.status).toBe(404);
  });
});

describe("POST /auth/invite", () => {
  it("sets the password, consumes the link and signs the user in", async () => {
    const calls: string[] = [];
    hooks.beforeSessionIssued = async ({ userId }) => {
      calls.push(userId);
    };
    const created = await invite();
    const res = await accept(created.token);
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/");
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    const cookies = sessionCookies(res);
    expect(calls).toEqual([created.id]);

    const me = await send("/api/v1/me", { cookies });
    expect(await me.json()).toMatchObject({ id: created.id, status: "active" });
    const row = await readUser(created.id);
    expect(await verifyPassword(NEW_PASSWORD, row?.passwordHash ?? "")).toBe(true);
    expect(await invitationRows()).toEqual([]);

    // Used links are invalid.
    await expectInvalid(await openLink(created.token));
    await expectInvalid(await accept(created.token, { password: "yet another passphrase" }));
    expect(await verifyPassword(NEW_PASSWORD, (await readUser(created.id))?.passwordHash ?? "")).toBe(true);
    await login("invited@example.com", NEW_PASSWORD);
  });

  it("redisplays the form for invalid passwords without consuming the link", async () => {
    const created = await invite();
    for (const [password, confirm, message] of [
      ["short", "short", "パスワードは 12 文字以上 256 文字以下にしてください"],
      [NEW_PASSWORD, `${NEW_PASSWORD}x`, "パスワードと確認用のパスワードが一致しません"],
    ] as const) {
      const res = await accept(created.token, { password, confirm });
      expect(res.status).toBe(400);
      const html = await res.text();
      expect(html).toContain('<ul role="alert">');
      expect(html).toContain(message);
      expect(html).toContain("invited@example.com");
    }
    expect((await readUser(created.id))?.passwordHash).toBeNull();
    expect(await invitationRows()).toHaveLength(1);
    expect((await accept(created.token)).status).toBe(303);
  });

  it("accepts the link only once for concurrent submissions", async () => {
    const created = await invite();
    const results = await Promise.all([
      accept(created.token, { password: "first passphrase!!" }),
      accept(created.token, { password: "second passphrase!!" }),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([303, 400]);
    const winner = results[0]?.status === 303 ? "first passphrase!!" : "second passphrase!!";
    expect(await verifyPassword(winner, (await readUser(created.id))?.passwordHash ?? "")).toBe(true);
    expect(await invitationRows()).toEqual([]);
  });

  it("starts MFA enrollment when the policy requires it, without a session", async () => {
    const mfaEnv = { PASSWORD_MFA_KEY: btoa("k".repeat(32)), APP_ORIGIN: ORIGIN, PASSWORD_MFA_POLICY: "all" };
    const calls: string[] = [];
    hooks.beforeSessionIssued = async ({ userId }) => {
      calls.push(userId);
    };
    const created = await invite("invited@example.com", { env: mfaEnv });
    const res = await accept(created.token, { env: mfaEnv });
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/auth/mfa");
    const cookies = setCookies(res);
    expect(cookies[AT]).toBeUndefined();
    expect(cookies[RT]).toBeUndefined();
    expect(cookies["__Host-testapp_mfa"]?.value).toBeTruthy();
    expect(calls).toEqual([]);
    expect(await verifyPassword(NEW_PASSWORD, (await readUser(created.id))?.passwordHash ?? "")).toBe(true);
  });

  it("returns 503 and sets no password when MFA is required but no method works at this URL", async () => {
    const created = await invite();
    // WebAuthn works only at APP_ORIGIN, and there is no TOTP key.
    const env = { APP_ORIGIN: "https://canonical.example.com", PASSWORD_MFA_POLICY: "all" };
    const res = await accept(created.token, { env });
    expect(res.status).toBe(503);
    expect((await readUser(created.id))?.passwordHash).toBeNull();
    expect(await invitationRows()).toHaveLength(1);
  });

  it("rejects the password login of an invited user", async () => {
    await invite();
    const res = await send("/auth/login", { form: { email: "invited@example.com", password: PASSWORD } });
    expect(res.status).toBe(401);
    expect(await res.text()).toContain("メールアドレスまたはパスワードが違います");
  });
});

describe("POST /api/v1/users/:id/invitation", () => {
  it("replaces the link: the old one becomes invalid", async () => {
    const created = await invite();
    const res = await send(`/api/v1/users/${created.id}/invitation`, { method: "POST", cookies: adminCookies });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { url: string; expires_at: number };
    expect(Object.keys(body).sort()).toEqual(["expires_at", "url"]);
    const token = new URL(body.url).searchParams.get("token") ?? "";
    expect(token).not.toBe(created.token);
    expect(await invitationRows()).toHaveLength(1);

    await expectInvalid(await openLink(created.token));
    expect((await openLink(token)).status).toBe(200);
    expect((await accept(token)).status).toBe(303);
  });

  it("returns 409 already_active for a user with a password, and 404 for an unknown user", async () => {
    const member = await createUser({ email: "member@example.com" });
    const active = await send(`/api/v1/users/${member.id}/invitation`, { method: "POST", cookies: adminCookies });
    expect(active.status).toBe(409);
    expect(await active.json()).toEqual({
      error: { code: "already_active", message: "このユーザーはすでにパスワードを設定しています" },
    });
    const unknown = await send(`/api/v1/users/${crypto.randomUUID()}/invitation`, { method: "POST", cookies: adminCookies });
    expect(unknown.status).toBe(404);
    expect(((await unknown.json()) as { error: { code: string } }).error.code).toBe("not_found");
    expect(await invitationRows()).toEqual([]);
  });

  it("returns 403 to members", async () => {
    const created = await invite();
    await createUser({ email: "member@example.com" });
    const memberCookies = await login("member@example.com");
    const res = await send(`/api/v1/users/${created.id}/invitation`, { method: "POST", cookies: memberCookies });
    expect(res.status).toBe(403);
  });
});

describe("invitations and other user changes", () => {
  it("invalidates the link when an admin sets the password", async () => {
    const created = await invite();
    const res = await send(`/api/v1/users/${created.id}/password`, { cookies: adminCookies, json: { password: NEW_PASSWORD } });
    expect(res.status).toBe(204);
    expect(await invitationRows()).toEqual([]);
    await expectInvalid(await openLink(created.token));
    await login("invited@example.com", NEW_PASSWORD);
  });

  it("deletes the link with the user", async () => {
    const created = await invite();
    const res = await send(`/api/v1/users/${created.id}`, { method: "DELETE", cookies: adminCookies });
    expect(res.status).toBe(204);
    expect(await invitationRows()).toEqual([]);
    await expectInvalid(await openLink(created.token));
  });
});
