import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clock } from "../src/clock.js";
import type { UserRow } from "../src/db/schema.js";
import { createTestAuthenticator } from "./fixture/webauthn.js";
import {
  AT,
  OIDC_ORIGIN,
  oidcEnv,
  ORIGIN,
  PASSWORD,
  RT,
  createUser,
  login,
  resetDb,
  send,
  sessionCookies,
  setCookies,
  type SessionCookies,
} from "./helpers.js";

const key = btoa("k".repeat(32));
const optional = { PASSWORD_MFA_KEY: key, APP_ORIGIN: ORIGIN };
const required = { ...optional, PASSWORD_MFA_POLICY: "all" };
const pendingCookie = "__Host-testapp_mfa";
const MFA_TABLES = ["mfa_accounts", "mfa_credentials", "mfa_recovery_codes", "mfa_pending"] as const;

type Env = typeof optional;
type Cookies = Record<string, string>;

function pendingCookies(response: Response): Cookies {
  const cookies = setCookies(response);
  expect(cookies[AT]).toBeUndefined();
  expect(cookies[RT]).toBeUndefined();
  const pending = cookies[pendingCookie];
  if (!pending) throw new Error("MFA pending cookie missing");
  return { [pendingCookie]: pending.value };
}

// A separate authenticator, using the base32 setup key shown to the user.
async function authenticatorCode(secret: string, now: number): Promise<string> {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = Array.from(secret, (c) => alphabet.indexOf(c).toString(2).padStart(5, "0")).join("");
  const keyBytes = Uint8Array.from(bits.match(/.{8}/g)!, (byte) => parseInt(byte, 2));
  const hmac = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = new ArrayBuffer(8);
  new DataView(counter).setBigUint64(0, BigInt(Math.floor(now / 30000)));
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmac, counter));
  const offset = mac[19]! & 15;
  return String((new DataView(mac.buffer).getUint32(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
}

function setupKey(html: string): string {
  const secret = /<code>([A-Z2-7]+)<\/code>/.exec(html)?.[1];
  if (!secret) throw new Error("TOTP setup key missing");
  return secret;
}

function recoveryCodes(html: string): string[] {
  const codes = Array.from(html.matchAll(/<li><code>([A-Z2-7-]+)<\/code><\/li>/g), (match) => match[1]!);
  expect(codes).toHaveLength(8);
  return codes;
}

async function beginLogin(userEmail: string, mfaEnv: Env, mfa = ""): Promise<Response> {
  return send("/auth/login", { env: mfaEnv, form: { email: userEmail, password: PASSWORD, next: "/wiki", mfa } });
}

// Registers a TOTP in an enrollment flow that is already started, and returns the secret, the recovery codes
// and the new session.
async function enrollTotp(pending: Cookies, mfaEnv: Env) {
  const start = await send("/auth/mfa/totp/start", { method: "POST", env: mfaEnv, cookies: pending });
  expect(start.status).toBe(200);
  const secret = setupKey(await start.text());
  const res = await send("/auth/mfa/totp", {
    env: mfaEnv,
    cookies: pending,
    form: { code: await authenticatorCode(secret, clock.now()) },
  });
  expect(res.status).toBe(200);
  const session = sessionCookies(res);
  return { secret, codes: recoveryCodes(await res.text()), session };
}

// Registers a TOTP as the first factor: /auth/login with mfa=enroll, then /auth/mfa/totp/start and /auth/mfa/totp.
async function enrolledWithTotp(user: UserRow, mfaEnv: Env) {
  return enrollTotp(pendingCookies(await beginLogin(user.email, mfaEnv, "enroll")), mfaEnv);
}

function resetMfa(id: string, cookies?: SessionCookies, mfaEnv: Env = optional): Promise<Response> {
  return send(`/api/v1/users/${id}/reset-mfa`, { method: "POST", env: mfaEnv, cookies });
}

async function countFor(table: (typeof MFA_TABLES)[number] | "sessions", userId: string): Promise<number> {
  const row = await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE user_id = ?`)
    .bind(userId)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

async function mfaCounts(userId: string): Promise<number[]> {
  return Promise.all(MFA_TABLES.map((table) => countFor(table, userId)));
}

async function markEnrolled(userId: string): Promise<void> {
  await env.DB.prepare("INSERT INTO mfa_accounts (user_id, revision) VALUES (?, 1)").bind(userId).run();
}

async function errorBody(res: Response): Promise<{ code: string; message: string }> {
  return ((await res.json()) as { error: { code: string; message: string } }).error;
}

let admin: UserRow;
let member: UserRow;
let adminCookies: SessionCookies;

beforeEach(async () => {
  await resetDb();
  admin = await createUser({ email: "admin@example.com", role: "admin" });
  member = await createUser({ email: "member@example.com" });
  adminCookies = await login(admin.email);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("POST /api/v1/users/:id/reset-mfa", () => {
  it("lets a member who lost the factors enroll new ones under the all policy", async () => {
    let now = Date.now();
    vi.spyOn(clock, "now").mockImplementation(() => now);
    const old = await enrolledWithTotp(member, required);
    const oldRecovery = old.codes[0]!;

    expect((await resetMfa(member.id, adminCookies, required)).status).toBe(204);

    // The next password login enters the enrollment flow, which does not accept the old recovery code.
    const enrollment = pendingCookies(await beginLogin(member.email, required));
    const recovered = await send("/auth/mfa/recovery", { env: required, cookies: enrollment, form: { code: oldRecovery } });
    expect(recovered.status).toBe(400);
    const fresh = await enrollTotp(enrollment, required);
    expect((await send("/api/v1/me", { env: required, cookies: fresh.session })).status).toBe(200);

    now += 30000;
    const pending = pendingCookies(await beginLogin(member.email, required));
    const oldTotp = await send("/auth/mfa/totp", {
      env: required,
      cookies: pending,
      form: { code: await authenticatorCode(old.secret, now) },
    });
    expect(oldTotp.status).toBe(400);
    const oldCode = await send("/auth/mfa/recovery", { env: required, cookies: pending, form: { code: oldRecovery } });
    expect(oldCode.status).toBe(400);
    const verified = await send("/auth/mfa/totp", {
      env: required,
      cookies: pending,
      form: { code: await authenticatorCode(fresh.secret, now) },
    });
    expect(verified.status).toBe(303);
    sessionCookies(verified);
  });

  it("lets the member sign in with the password only under the optional policy", async () => {
    await enrolledWithTotp(member, optional);
    expect(pendingCookies(await beginLogin(member.email, optional))).toBeDefined();

    expect((await resetMfa(member.id, adminCookies)).status).toBe(204);

    const res = await beginLogin(member.email, optional);
    expect(res.status).toBe(303);
    sessionCookies(res);
  });

  it("deletes every factor, recovery code and pending flow of the user only", async () => {
    let now = Date.now();
    vi.spyOn(clock, "now").mockImplementation(() => now);
    // A passkey as the first factor, then a TOTP added through the manage flow with the passkey as proof.
    const authenticator = await createTestAuthenticator(ORIGIN);
    const options = async (cookies: Cookies) => {
      const res = await send("/auth/mfa/webauthn/options", { env: optional, cookies, json: {} });
      expect(res.status).toBe(200);
      return (await res.json<{ challenge: string }>()).challenge;
    };
    const enrollment = pendingCookies(await beginLogin(member.email, optional, "enroll"));
    const registration = await authenticator.register(await options(enrollment));
    const registered = await send("/auth/mfa/webauthn/verify", {
      env: optional,
      cookies: enrollment,
      form: { response: JSON.stringify(registration) },
    });
    expect(registered.status).toBe(200);
    sessionCookies(registered);
    const manage = pendingCookies(await beginLogin(member.email, optional, "enroll"));
    const proof = await authenticator.authenticate(await options(manage));
    const proven = await send("/auth/mfa/webauthn/verify", {
      env: optional,
      cookies: manage,
      form: { response: JSON.stringify(proof) },
    });
    expect(proven.status).toBe(303);
    const start = await send("/auth/mfa/totp/start", { method: "POST", env: optional, cookies: manage });
    expect(start.status).toBe(200);
    const secret = setupKey(await start.text());
    const added = await send("/auth/mfa/totp", {
      env: optional,
      cookies: manage,
      form: { code: await authenticatorCode(secret, now) },
    });
    expect([200, 303]).toContain(added.status);
    sessionCookies(added);
    // A sign-in left in the middle.
    const stalled = pendingCookies(await beginLogin(member.email, optional));

    const other = await createUser({ email: "other@example.com" });
    await enrolledWithTotp(other, optional);
    pendingCookies(await beginLogin(other.email, optional));

    const [accounts, credentials, codes, pendings] = await mfaCounts(member.id);
    expect(accounts).toBe(1);
    expect(credentials).toBe(1);
    expect(codes).toBeGreaterThan(0);
    expect(pendings).toBeGreaterThan(0);
    const otherBefore = await mfaCounts(other.id);
    expect(otherBefore).toEqual([1, 0, 8, 1]);

    expect((await resetMfa(member.id, adminCookies)).status).toBe(204);

    expect(await mfaCounts(member.id)).toEqual([0, 0, 0, 0]);
    expect(await mfaCounts(other.id)).toEqual(otherBefore);
    expect((await send("/auth/mfa", { env: optional, cookies: stalled })).status).toBe(401);

    // After a new enrollment, the old passkey is not accepted.
    now += 30000;
    await enrolledWithTotp(member, optional);
    const pending = pendingCookies(await beginLogin(member.email, optional));
    const assertion = await authenticator.authenticate(await options(pending));
    const rejected = await send("/auth/mfa/webauthn/verify", {
      env: optional,
      cookies: pending,
      form: { response: JSON.stringify(assertion) },
    });
    expect(rejected.status).toBe(400);
  });

  it("revokes the sessions and sets mcp_revoked_at, keeping the requester's session", async () => {
    const memberCookies = await login(member.email);
    await markEnrolled(member.id);
    const now = Date.now() + 1000;
    vi.spyOn(clock, "now").mockImplementation(() => now);

    expect((await resetMfa(member.id, adminCookies)).status).toBe(204);

    expect((await send("/api/v1/me", { cookies: memberCookies })).status).toBe(401);
    const sessions = await env.DB.prepare("SELECT revoked_at FROM sessions WHERE user_id = ?")
      .bind(member.id)
      .all<{ revoked_at: number | null }>();
    expect(sessions.results).toEqual([{ revoked_at: now }]);
    expect(await env.DB.prepare("SELECT mcp_revoked_at FROM users WHERE id = ?").bind(member.id).first("mcp_revoked_at"))
      .toBe(now);
    expect(await env.DB.prepare("SELECT mcp_revoked_at FROM users WHERE id = ?").bind(admin.id).first("mcp_revoked_at"))
      .toBeNull();
    expect((await send("/api/v1/me", { cookies: adminCookies })).status).toBe(200);
  });

  it("refuses to reset the requester's own MFA", async () => {
    await markEnrolled(admin.id);
    const res = await resetMfa(admin.id, adminCookies);
    expect(res.status).toBe(400);
    expect(await errorBody(res)).toEqual({ code: "cannot_reset_own_mfa", message: "自分自身の多要素認証はリセットできません" });
    expect(await countFor("mfa_accounts", admin.id)).toBe(1);
  });

  it("answers 404 for an unknown user", async () => {
    const res = await resetMfa(crypto.randomUUID(), adminCookies);
    expect(res.status).toBe(404);
    expect(await errorBody(res)).toEqual({ code: "not_found", message: "ユーザーが見つかりません" });
  });

  it("answers 409 for a user without MFA, and for an enrollment that was only started", async () => {
    const memberCookies = await login(member.email);
    const none = await resetMfa(member.id, adminCookies);
    expect(none.status).toBe(409);
    expect(await errorBody(none)).toEqual({ code: "mfa_not_enrolled", message: "このユーザーは多要素認証を設定していません" });
    expect((await send("/api/v1/me", { cookies: memberCookies })).status).toBe(200);

    pendingCookies(await beginLogin(member.email, optional, "enroll"));
    expect(await env.DB.prepare("SELECT revision FROM mfa_accounts WHERE user_id = ?").bind(member.id).first("revision"))
      .toBe(0);
    const started = await resetMfa(member.id, adminCookies);
    expect(started.status).toBe(409);
    expect((await errorBody(started)).code).toBe("mfa_not_enrolled");
    expect((await send("/api/v1/me", { cookies: memberCookies })).status).toBe(200);
    expect(await countFor("mfa_pending", member.id)).toBe(1);
  });

  it("rejects members, anonymous requests and the oidc mode", async () => {
    const memberCookies = await login(member.email);
    await markEnrolled(member.id);
    const byMember = await resetMfa(admin.id, memberCookies);
    expect(byMember.status).toBe(403);
    expect((await errorBody(byMember)).code).toBe("forbidden");

    const anonymous = await resetMfa(member.id);
    expect(anonymous.status).toBe(401);
    expect((await errorBody(anonymous)).code).toBe("unauthorized");

    const oidc = await send(`${OIDC_ORIGIN}/api/v1/users/${member.id}/reset-mfa`, { method: "POST", env: oidcEnv });
    expect(oidc.status).toBe(404);

    expect(await countFor("mfa_accounts", member.id)).toBe(1);
  });
});
