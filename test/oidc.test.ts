import { eq } from "drizzle-orm";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { env as workerEnv } from "cloudflare:workers";
import { evaluateIdTokenClaims, isEmailVerified } from "../src/auth/oidc.js";
import { base64UrlEncode } from "../src/auth/tokens.js";
import { resolveOidcUser, type OidcIdentity } from "../src/auth/users.js";
import { sessions, users } from "../src/db/schema.js";
import { loadConfig, type CoreBindings } from "../src/config.js";
import {
  createUser,
  db,
  dbChangingBefore,
  OIDC_ORIGIN,
  oidcEnv,
  resetDb,
  send,
  sessionCookies,
  setCookies,
} from "./helpers.js";
import { hooks } from "./fixture/src/index.js";

const ISSUER = oidcEnv.OIDC_ISSUER ?? "";
const CLIENT_ID = oidcEnv.OIDC_CLIENT_ID ?? "";
const NOW = Date.UTC(2026, 9, 1);

function identity(overrides: Partial<OidcIdentity> = {}): OidcIdentity {
  return { issuer: ISSUER, subject: "sub-1", email: "alice@example.com", name: "Alice", ...overrides };
}

beforeEach(resetDb);

const ADMIN_EMAIL = "alice@example.com";
const asInitialAdmin = { initialAdminEmail: ADMIN_EMAIL };

describe("resolveOidcUser", () => {
  it("creates the first admin for INITIAL_ADMIN_EMAIL while there are no users", async () => {
    const result = await resolveOidcUser(db, identity(), NOW, asInitialAdmin);
    expect(result).toMatchObject({
      ok: true,
      user: { role: "admin", email: ADMIN_EMAIL, name: "Alice", oidcIssuer: ISSUER, oidcSubject: "sub-1", passwordHash: null },
    });
    expect(await db.select().from(users).all()).toHaveLength(1);
  });

  it("rejects everyone as not_invited without INITIAL_ADMIN_EMAIL and writes nothing", async () => {
    const allowWrite = vi.fn().mockResolvedValue(true);
    expect(await resolveOidcUser(db, identity(), NOW, { allowWrite })).toEqual({ ok: false, reason: "not_invited" });
    expect(await resolveOidcUser(db, identity(), NOW, { initialAdminEmail: null, allowWrite })).toEqual({
      ok: false,
      reason: "not_invited",
    });
    expect(allowWrite).not.toHaveBeenCalled();
    expect(await db.select().from(users).all()).toHaveLength(0);
  });

  it("rejects an email other than INITIAL_ADMIN_EMAIL while there are no users", async () => {
    const result = await resolveOidcUser(db, identity({ email: "bob@example.com" }), NOW, asInitialAdmin);
    expect(result).toEqual({ ok: false, reason: "not_invited" });
    expect(await db.select().from(users).all()).toHaveLength(0);
  });

  it("ignores INITIAL_ADMIN_EMAIL once a user exists", async () => {
    await createUser({ email: "bob@example.com", role: "admin" });
    const userCreatedStatements = vi.fn().mockReturnValue([]);
    const result = await resolveOidcUser(db, identity(), NOW, { ...asInitialAdmin, userCreatedStatements });
    expect(result).toEqual({ ok: false, reason: "not_invited" });
    expect(userCreatedStatements).not.toHaveBeenCalled();
    expect(await db.select().from(users).all()).toHaveLength(1);
  });

  it("creates one admin for concurrent first logins of the same person", async () => {
    const results = await Promise.all([
      resolveOidcUser(db, identity(), NOW, asInitialAdmin),
      resolveOidcUser(db, identity(), NOW, asInitialAdmin),
    ]);
    const all = await db.select().from(users).all();
    expect(all).toHaveLength(1);
    expect(all[0]?.role).toBe("admin");
    expect(results.map((r) => (r.ok ? r.user.id : r.reason))).toEqual([all[0]?.id, all[0]?.id]);
  });

  it("retries when another user is created before the INSERT of the first admin", async () => {
    const changing = dbChangingBefore(/WHERE NOT EXISTS \(SELECT 1 FROM users\)/, () =>
      createUser({ email: "bob@example.com", role: "admin" }),
    );
    expect(await resolveOidcUser(changing, identity(), NOW, asInitialAdmin)).toEqual({ ok: false, reason: "not_invited" });
    const all = await db.select().from(users).all();
    expect(all.map((u) => u.email)).toEqual(["bob@example.com"]);
  });

  it("finds a linked user by issuer and subject and updates the email", async () => {
    const created = await resolveOidcUser(db, identity(), NOW, asInitialAdmin);
    const again = await resolveOidcUser(db, identity({ email: "alice@new.example.com" }), NOW + 1);
    expect(again.ok && again.user.id).toBe(created.ok && created.user.id);
    const row = await db.select().from(users).where(eq(users.oidcSubject, "sub-1")).get();
    expect(row?.email).toBe("alice@new.example.com");
  });

  it("keeps the old email when the new one belongs to another user", async () => {
    await resolveOidcUser(db, identity(), NOW, asInitialAdmin);
    await createUser({ email: "taken@example.com" });
    const again = await resolveOidcUser(db, identity({ email: "taken@example.com" }), NOW + 1);
    expect(again).toMatchObject({ ok: true, user: { email: "alice@example.com", oidcSubject: "sub-1" } });
  });

  it("links an invited user without changing the role, name or creation time", async () => {
    await createUser({ email: "admin@example.com", role: "admin" });
    const invited = await createUser({ email: "alice@example.com", role: "member", password: null, createdAt: 1000 });
    const result = await resolveOidcUser(db, identity(), NOW, asInitialAdmin);
    expect(result).toMatchObject({
      ok: true,
      user: { id: invited.id, role: "member", name: null, createdAt: 1000, oidcIssuer: ISSUER, oidcSubject: "sub-1" },
    });
    expect(await db.select().from(users).all()).toHaveLength(2);
  });

  it("rejects a user deleted before the first sign-in", async () => {
    await createUser({ email: "admin@example.com", role: "admin" });
    const invited = await createUser({ email: "alice@example.com", password: null });
    await db.delete(users).where(eq(users.id, invited.id)).run();
    expect(await resolveOidcUser(db, identity(), NOW)).toEqual({ ok: false, reason: "not_invited" });
    expect(await db.select().from(users).all()).toHaveLength(1);
  });

  it("rejects an email that is linked to a different issuer or subject", async () => {
    await resolveOidcUser(db, identity(), NOW, asInitialAdmin);
    expect(await resolveOidcUser(db, identity({ subject: "other-sub" }), NOW, asInitialAdmin)).toEqual({
      ok: false,
      reason: "conflict",
    });
    expect(await resolveOidcUser(db, identity({ issuer: "https://other-idp.example.com" }), NOW)).toEqual({
      ok: false,
      reason: "conflict",
    });
    expect(await db.select().from(users).all()).toHaveLength(1);
  });
});

describe("ID token claims", () => {
  it("requires email_verified to be the boolean true", () => {
    expect(isEmailVerified({ email_verified: true }, true)).toBe(true);
    expect(isEmailVerified({ email_verified: false }, true)).toBe(false);
    expect(isEmailVerified({ email_verified: "true" }, true)).toBe(false);
    expect(isEmailVerified({}, true)).toBe(false);
    expect(isEmailVerified({ email_verified: undefined }, true)).toBe(false);
  });

  it("accepts only a missing email_verified when it is not required", () => {
    expect(isEmailVerified({ email_verified: true }, false)).toBe(true);
    expect(isEmailVerified({}, false)).toBe(true);
    expect(isEmailVerified({ email_verified: undefined }, false)).toBe(true);
    expect(isEmailVerified({ email_verified: false }, false)).toBe(false);
    expect(isEmailVerified({ email_verified: "true" }, false)).toBe(false);
    expect(isEmailVerified({ email_verified: null }, false)).toBe(false);
  });

  it("evaluates email and email_verified", () => {
    const opts = { requireEmailVerified: true };
    const base = { email: " Alice@Example.com ", email_verified: true, name: " Alice " };
    // Any domain passes: who may sign in is decided by the users table.
    expect(evaluateIdTokenClaims(base, opts)).toEqual({ ok: true, email: "alice@example.com", name: "Alice" });
    expect(evaluateIdTokenClaims({ ...base, email: "bob@outside.test" }, opts)).toMatchObject({ ok: true });
    expect(evaluateIdTokenClaims({ ...base, name: "a".repeat(101) }, opts)).toMatchObject({ ok: true, name: null });
    expect(evaluateIdTokenClaims({ email_verified: true }, opts)).toEqual({ ok: false, reason: "invalid_email" });
    expect(evaluateIdTokenClaims({ ...base, email: "bad" }, opts)).toEqual({ ok: false, reason: "invalid_email" });
    expect(evaluateIdTokenClaims({ ...base, email_verified: false }, opts)).toEqual({
      ok: false,
      reason: "email_not_verified",
    });
    expect(evaluateIdTokenClaims({ ...base, email_verified: "true" }, opts)).toEqual({
      ok: false,
      reason: "email_not_verified",
    });
    expect(evaluateIdTokenClaims({ email: base.email }, opts)).toEqual({ ok: false, reason: "email_not_verified" });
  });

  it("evaluates claims when email_verified is not required", () => {
    const opts = { requireEmailVerified: false };
    const base = { email: " Alice@Example.com ", name: " Alice " };
    expect(evaluateIdTokenClaims(base, opts)).toEqual({ ok: true, email: "alice@example.com", name: "Alice" });
    expect(evaluateIdTokenClaims({ ...base, email_verified: true }, opts)).toMatchObject({ ok: true });
    for (const value of [false, "true", null]) {
      expect(evaluateIdTokenClaims({ ...base, email_verified: value }, opts)).toEqual({
        ok: false,
        reason: "email_not_verified",
      });
    }
    expect(evaluateIdTokenClaims({ ...base, email: "bad" }, opts)).toEqual({ ok: false, reason: "invalid_email" });
    expect(evaluateIdTokenClaims({ ...base, email: "bad", email_verified: false }, opts)).toEqual({
      ok: false,
      reason: "invalid_email",
    });
  });
});

describe("loadConfig OIDC_REQUIRE_EMAIL_VERIFIED", () => {
  const load = (overrides: Partial<CoreBindings>) => loadConfig({ ...workerEnv, ...oidcEnv, ...overrides } as CoreBindings);

  it.each([
    ["true", true],
    ["false", false],
    [undefined, true],
    ["", true],
  ])("accepts %j as requireEmailVerified=%j", (value, expected) => {
    const result = load({ OIDC_REQUIRE_EMAIL_VERIFIED: value });
    expect(result.ok).toBe(true);
    expect(result.ok && result.config.oidc?.requireEmailVerified).toBe(expected);
  });

  it.each([["FALSE"], ["0"], [false as unknown as string]])("rejects %j", (value) => {
    const result = load({ OIDC_REQUIRE_EMAIL_VERIFIED: value });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.invalid).toContain("OIDC_REQUIRE_EMAIL_VERIFIED");
  });

  it("ignores the value in password mode", () => {
    const result = loadConfig({ ...workerEnv, AUTH_MODE: "password", OIDC_REQUIRE_EMAIL_VERIFIED: "bogus" } as CoreBindings);
    expect(result.ok).toBe(true);
  });
});

describe("OIDC flow with a mocked IdP", () => {
  // The first sign-in of alice@example.com to an empty deployment creates the first admin.
  const adminEnv: Partial<CoreBindings> = { ...oidcEnv, INITIAL_ADMIN_EMAIL: ADMIN_EMAIL };
  const KID = "test-key";
  let keyPair: CryptoKeyPair;
  let otherKeyPair: CryptoKeyPair;
  let signingKey: CryptoKey;
  let publicJwk: JsonWebKey;
  let idTokenClaims: Record<string, unknown>;
  let tokenRequests: { authorization: string | null; body: URLSearchParams }[];

  beforeAll(async () => {
    const generate = async () =>
      (await crypto.subtle.generateKey(
        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true,
        ["sign", "verify"],
      )) as CryptoKeyPair;
    keyPair = await generate();
    otherKeyPair = await generate();
    publicJwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as JsonWebKey;
  });

  async function signIdToken(claims: Record<string, unknown>): Promise<string> {
    const encode = (value: unknown) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
    const input = `${encode({ alg: "RS256", kid: KID, typ: "JWT" })}.${encode(claims)}`;
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signingKey, new TextEncoder().encode(input));
    return `${input}.${base64UrlEncode(new Uint8Array(signature))}`;
  }

  beforeEach(() => {
    tokenRequests = [];
    signingKey = keyPair.privateKey;
    idTokenClaims = { email: "alice@example.com", email_verified: true, name: "Alice" };
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      const json = (body: unknown) =>
        new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
      if (url.href === `${ISSUER}/.well-known/openid-configuration`) {
        return json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
        });
      }
      if (url.href === `${ISSUER}/jwks`) {
        return json({ keys: [{ ...publicJwk, kid: KID, alg: "RS256", use: "sig" }] });
      }
      if (url.href === `${ISSUER}/token`) {
        const body = new URLSearchParams(new TextDecoder().decode(await request.arrayBuffer()));
        tokenRequests.push({ authorization: request.headers.get("Authorization"), body });
        const now = Math.floor(Date.now() / 1000);
        const idToken = await signIdToken({
          iss: ISSUER,
          sub: "sub-1",
          aud: CLIENT_ID,
          iat: now,
          exp: now + 300,
          nonce: pendingNonce,
          ...idTokenClaims,
        });
        return json({ access_token: "access", token_type: "Bearer", expires_in: 300, id_token: idToken });
      }
      return new Response("not found", { status: 404 });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  let pendingNonce = "";

  async function startLogin(next = "/wiki", env: Partial<CoreBindings> = adminEnv) {
    const res = await send(`${OIDC_ORIGIN}/auth/login?next=${encodeURIComponent(next)}`, { env });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("Location") ?? "");
    pendingNonce = location.searchParams.get("nonce") ?? "";
    const oidcCookie = setCookies(res)["__Host-testapp_oidc"];
    expect(oidcCookie?.maxAge).toBe(600);
    return { location, oidcCookie: oidcCookie?.value ?? "" };
  }

  function callback(query: string, oidcCookie?: string, env: Partial<CoreBindings> = adminEnv) {
    return send(`${OIDC_ORIGIN}/auth/oidc/callback?${query}`, {
      env,
      cookies: oidcCookie ? { "__Host-testapp_oidc": oidcCookie } : undefined,
    });
  }

  it("redirects to the IdP with PKCE and signs the user in on callback", async () => {
    const { location, oidcCookie } = await startLogin();
    expect(`${location.origin}${location.pathname}`).toBe(`${ISSUER}/authorize`);
    expect(location.searchParams.get("redirect_uri")).toBe(`${OIDC_ORIGIN}/auth/oidc/callback`);
    expect(location.searchParams.get("scope")).toBe("openid email profile");
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    expect(location.searchParams.get("client_id")).toBe(CLIENT_ID);

    const state = location.searchParams.get("state") ?? "";
    const res = await callback(`code=abc&state=${state}`, oidcCookie);
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/wiki");
    expect(setCookies(res)["__Host-testapp_oidc"]?.maxAge).toBe(0);
    const cookies = sessionCookies(res);
    expect(setCookies(res)["__Host-testapp_rt"]?.maxAge).toBe(24 * 60 * 60);

    expect(tokenRequests).toHaveLength(1);
    expect(tokenRequests[0]?.authorization).toMatch(/^Basic /);
    expect(tokenRequests[0]?.body.get("code")).toBe("abc");
    expect(tokenRequests[0]?.body.get("redirect_uri")).toBe(`${OIDC_ORIGIN}/auth/oidc/callback`);
    expect(tokenRequests[0]?.body.get("code_verifier")).toBeTruthy();

    const me = await send(`${OIDC_ORIGIN}/api/v1/me`, { env: oidcEnv, cookies });
    expect(await me.json()).toMatchObject({ email: "alice@example.com", name: "Alice", role: "admin" });
    const user = await db.select().from(users).where(eq(users.oidcSubject, "sub-1")).get();
  });

  it("returns 400 when the ID token signature or nonce is invalid", async () => {
    signingKey = otherKeyPair.privateKey;
    let { location, oidcCookie } = await startLogin();
    expect((await callback(`code=abc&state=${location.searchParams.get("state")}`, oidcCookie)).status).toBe(400);

    signingKey = keyPair.privateKey;
    ({ location, oidcCookie } = await startLogin());
    pendingNonce = "other-nonce";
    expect((await callback(`code=abc&state=${location.searchParams.get("state")}`, oidcCookie)).status).toBe(400);
    expect(await db.select().from(users).all()).toHaveLength(0);
  });

  it("returns 400 when the state does not match or the cookie is missing", async () => {
    const { oidcCookie } = await startLogin();
    const mismatch = await callback("code=abc&state=wrong", oidcCookie);
    expect(mismatch.status).toBe(400);
    expect(setCookies(mismatch)["__Host-testapp_oidc"]?.maxAge).toBe(0);
    expect((await callback("code=abc&state=wrong")).status).toBe(400);
    expect((await callback("error=access_denied&state=wrong")).status).toBe(400);
    expect(tokenRequests).toHaveLength(0);
  });

  it("returns 400 when the IdP returns an error", async () => {
    const { location, oidcCookie } = await startLogin();
    const state = location.searchParams.get("state") ?? "";
    const res = await callback(`error=access_denied&state=${state}`, oidcCookie);
    expect(res.status).toBe(400);
    expect(await res.text()).not.toContain("access_denied");
    expect(tokenRequests).toHaveLength(0);
  });

  it.each([
    [{ email_verified: false }],
    [{ email_verified: "true" }],
    [{ email_verified: undefined }],
    [{ email: undefined }],
  ])("returns 403 and creates no user for %j", async (override) => {
    idTokenClaims = { ...idTokenClaims, ...override };
    const { location, oidcCookie } = await startLogin();
    const res = await callback(`code=abc&state=${location.searchParams.get("state")}`, oidcCookie);
    expect(res.status).toBe(403);
    expect(await db.select().from(users).all()).toHaveLength(0);
  });

  it("signs in without email_verified when it is not required", async () => {
    const env = { ...adminEnv, OIDC_REQUIRE_EMAIL_VERIFIED: "false" };
    idTokenClaims = { email: "alice@example.com", name: "Alice" };
    const { location, oidcCookie } = await startLogin("/wiki", env);
    const res = await callback(`code=abc&state=${location.searchParams.get("state")}`, oidcCookie, env);
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/wiki");
    expect(await db.select().from(users).all()).toHaveLength(1);
  });

  it("returns 403 for email_verified false even when it is not required", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const env = { ...oidcEnv, OIDC_REQUIRE_EMAIL_VERIFIED: "false" };
    idTokenClaims = { ...idTokenClaims, email_verified: false };
    const { location, oidcCookie } = await startLogin("/wiki", env);
    const res = await callback(`code=abc&state=${location.searchParams.get("state")}`, oidcCookie, env);
    expect(res.status).toBe(403);
    expect(await db.select().from(users).all()).toHaveLength(0);
    expect(warn).toHaveBeenCalledWith("oidc login rejected", { reason: "email_not_verified", email_verified: "boolean" });
    expect(JSON.stringify(warn.mock.calls)).not.toContain("alice@example.com");
  });

  it("logs only the type of a missing email_verified on rejection", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    idTokenClaims = { email: "alice@example.com", name: "Alice" };
    const { location, oidcCookie } = await startLogin();
    const res = await callback(`code=abc&state=${location.searchParams.get("state")}`, oidcCookie);
    expect(res.status).toBe(403);
    expect(warn).toHaveBeenCalledWith("oidc login rejected", { reason: "email_not_verified", email_verified: "undefined" });
    expect(JSON.stringify(warn.mock.calls)).not.toContain("alice@example.com");
  });

  async function loginWith(env: Partial<CoreBindings>) {
    const { location, oidcCookie } = await startLogin("/wiki", env);
    return callback(`code=abc&state=${location.searchParams.get("state")}`, oidcCookie, env);
  }

  it("returns 403 and logs initial_admin_not_configured without users and INITIAL_ADMIN_EMAIL", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const res = await loginWith(oidcEnv);
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("このアカウントではログインできません");
    expect(await db.select().from(users).all()).toHaveLength(0);
    expect(await db.select().from(sessions).all()).toHaveLength(0);
    expect(warn).toHaveBeenCalledWith("oidc login rejected", { reason: "initial_admin_not_configured" });
    expect(JSON.stringify(warn.mock.calls)).not.toContain("alice@example.com");
  });

  it("returns 403 not_invited for an email other than INITIAL_ADMIN_EMAIL without users", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const res = await loginWith({ ...oidcEnv, INITIAL_ADMIN_EMAIL: "bob@example.com" });
    expect(res.status).toBe(403);
    expect(await db.select().from(users).all()).toHaveLength(0);
    expect(await db.select().from(sessions).all()).toHaveLength(0);
    expect(warn).toHaveBeenCalledWith("oidc login rejected", { reason: "not_invited" });
    expect(JSON.stringify(warn.mock.calls)).not.toContain("alice@example.com");
  });

  it("returns 403 not_invited for an unregistered email once a user exists, even for INITIAL_ADMIN_EMAIL", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await createUser({ email: "bob@example.com", role: "admin" });
    for (const env of [adminEnv, oidcEnv]) {
      const res = await loginWith(env);
      expect(res.status).toBe(403);
    }
    expect(await db.select().from(users).all()).toHaveLength(1);
    expect(await db.select().from(sessions).all()).toHaveLength(0);
    expect(warn.mock.calls).toEqual([
      ["oidc login rejected", { reason: "not_invited" }],
      ["oidc login rejected", { reason: "not_invited" }],
    ]);
  });

  it("signs in an invited user with the registered role and links the identity", async () => {
    await createUser({ email: "bob@example.com", role: "admin" });
    const invited = await createUser({ email: "alice@example.com", role: "member", password: null });
    const res = await loginWith(oidcEnv);
    expect(res.status).toBe(303);
    const cookies = sessionCookies(res);
    const me = await send(`${OIDC_ORIGIN}/api/v1/me`, { env: oidcEnv, cookies });
    expect(await me.json()).toMatchObject({ id: invited.id, role: "member", status: "active" });
    expect(await db.select().from(users).where(eq(users.id, invited.id)).get()).toMatchObject({
      oidcIssuer: ISSUER,
      oidcSubject: "sub-1",
    });
  });

  it("links a user registered through POST /api/v1/users on their first sign-in", async () => {
    const adminLogin = await loginWith(adminEnv);
    expect(adminLogin.status).toBe(303);
    const adminCookies = sessionCookies(adminLogin);
    const created = await send(`${OIDC_ORIGIN}/api/v1/users`, {
      env: oidcEnv,
      cookies: adminCookies,
      json: { email: "Bob@Example.com", role: "member" },
    });
    expect(created.status).toBe(201);
    const bob = (await created.json()) as { id: string; status: string };
    expect(bob.status).toBe("invited");

    idTokenClaims = { ...idTokenClaims, sub: "sub-bob", email: "bob@example.com", name: "Bob" };
    const res = await loginWith(oidcEnv);
    expect(res.status).toBe(303);
    const me = await send(`${OIDC_ORIGIN}/api/v1/me`, { env: oidcEnv, cookies: sessionCookies(res) });
    expect(await me.json()).toMatchObject({ id: bob.id, role: "member", status: "active" });
    expect(await db.select().from(users).where(eq(users.id, bob.id)).get()).toMatchObject({ oidcSubject: "sub-bob" });
  });

  it("returns 403 for a user deleted before the first sign-in", async () => {
    await createUser({ email: "bob@example.com", role: "admin" });
    const invited = await createUser({ email: "alice@example.com", password: null });
    await db.delete(users).where(eq(users.id, invited.id)).run();
    const res = await loginWith(oidcEnv);
    expect(res.status).toBe(403);
    expect(await db.select().from(users).all()).toHaveLength(1);
    expect(await db.select().from(sessions).all()).toHaveLength(0);
  });

  it("does not link an invited user whose email is not verified", async () => {
    await createUser({ email: "bob@example.com", role: "admin" });
    const invited = await createUser({ email: "alice@example.com", password: null });
    idTokenClaims = { ...idTokenClaims, email_verified: false };
    const res = await loginWith(oidcEnv);
    expect(res.status).toBe(403);
    expect(await db.select().from(users).where(eq(users.id, invited.id)).get()).toMatchObject({ oidcSubject: null });
    expect(await db.select().from(sessions).all()).toHaveLength(0);
  });

  it("ignores ALLOWED_EMAILS left in the environment", async () => {
    const leftover: Record<string, string> = { ALLOWED_EMAILS: "" };
    const res = await loginWith({ ...adminEnv, ...leftover });
    expect(res.status).toBe(303);
    expect(await db.select().from(users).all()).toHaveLength(1);
  });

  it("skips beforeOidcUserLinkOrCreate for uninvited emails", async () => {
    const check = vi.fn<NonNullable<typeof hooks.beforeOidcUserLinkOrCreate>>().mockResolvedValue(true);
    hooks.beforeOidcUserLinkOrCreate = check;
    expect((await loginWith(oidcEnv)).status).toBe(403);
    expect(check).not.toHaveBeenCalled();
    expect(await db.select().from(users).all()).toHaveLength(0);
  });

  it("denies first registration before creating a user or session", async () => {
    idTokenClaims = { ...idTokenClaims, email: " Alice@Example.com ", hd: "example.com" };
    const check = vi.fn<NonNullable<typeof hooks.beforeOidcUserLinkOrCreate>>().mockResolvedValue(false);
    hooks.beforeOidcUserLinkOrCreate = check;
    expect((await loginWith(adminEnv)).status).toBe(403);
    expect(check).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
      operation: "create", email: "alice@example.com", issuer: ISSUER, subject: "sub-1",
      claims: expect.objectContaining({ hd: "example.com", email_verified: true }),
    }));
    expect(await db.select().from(users).all()).toHaveLength(0);
    expect(await db.select().from(sessions).all()).toHaveLength(0);
  });

  it("checks initial linking before updating and skips subsequent logins of the linked subject", async () => {
    const existing = await createUser({ email: "alice@example.com" });
    const check = vi.fn<NonNullable<typeof hooks.beforeOidcUserLinkOrCreate>>()
      .mockResolvedValueOnce(false).mockResolvedValueOnce(true).mockResolvedValue(false);
    hooks.beforeOidcUserLinkOrCreate = check;
    expect((await loginWith(oidcEnv)).status).toBe(403);
    expect(await db.select().from(users).where(eq(users.id, existing.id)).get()).toMatchObject({ oidcSubject: null });
    expect(await db.select().from(sessions).all()).toHaveLength(0);
    expect((await loginWith(oidcEnv)).status).toBe(303);
    idTokenClaims = { ...idTokenClaims, email: "new@example.com" };
    expect((await loginWith(oidcEnv)).status).toBe(303);
    expect(check.mock.calls.map(([args]) => args.operation)).toEqual(["link", "link"]);
    expect(await db.select().from(users).where(eq(users.id, existing.id)).get()).toMatchObject({
      email: "new@example.com", oidcSubject: "sub-1",
    });
  });

  it("fails closed when the initial identity check throws", async () => {
    hooks.beforeOidcUserLinkOrCreate = async () => { throw new Error("identity check failed"); };
    expect((await loginWith(adminEnv)).status).toBe(500);
    expect(await db.select().from(users).all()).toHaveLength(0);
    expect(await db.select().from(sessions).all()).toHaveLength(0);
  });

  describe("OIDC_REQUIRE_GOOGLE_HD", () => {
    const requireHd: Partial<CoreBindings> = { ...oidcEnv, OIDC_REQUIRE_GOOGLE_HD: "true" };
    const requireHdAdmin: Partial<CoreBindings> = { ...adminEnv, OIDC_REQUIRE_GOOGLE_HD: "true" };

    async function invite() {
      await createUser({ email: "bob@example.com", role: "admin" });
      return createUser({ email: "alice@example.com", role: "member", password: null });
    }

    it("returns 403 without linking an invited user whose token has no hd", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const invited = await invite();
      const res = await loginWith(requireHd);
      expect(res.status).toBe(403);
      expect(await res.text()).toContain("このアカウントではログインできません");
      expect(await db.select().from(users).where(eq(users.id, invited.id)).get()).toMatchObject({ oidcSubject: null });
      expect(await db.select().from(sessions).all()).toHaveLength(0);
      expect(warn).toHaveBeenCalledWith("oidc login rejected", { reason: "google_hd_missing", hd: "undefined" });
      expect(JSON.stringify(warn.mock.calls)).not.toContain("alice@example.com");
    });

    it.each([[""], ["  "], [true]])("returns 403 for an invited user with hd %j", async (hd) => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const invited = await invite();
      idTokenClaims = { ...idTokenClaims, hd };
      expect((await loginWith(requireHd)).status).toBe(403);
      expect(await db.select().from(users).where(eq(users.id, invited.id)).get()).toMatchObject({ oidcSubject: null });
      expect(warn).toHaveBeenCalledWith("oidc login rejected", { reason: "google_hd_missing", hd: typeof hd });
    });

    it("links an invited user whose token has hd", async () => {
      const invited = await invite();
      idTokenClaims = { ...idTokenClaims, hd: "example.com" };
      expect((await loginWith(requireHd)).status).toBe(303);
      expect(await db.select().from(users).where(eq(users.id, invited.id)).get()).toMatchObject({ oidcSubject: "sub-1" });
    });

    it("creates the first admin with a Gmail address without hd", async () => {
      idTokenClaims = { ...idTokenClaims, email: "alice@gmail.com" };
      const res = await loginWith({ ...requireHdAdmin, INITIAL_ADMIN_EMAIL: "alice@gmail.com" });
      expect(res.status).toBe(303);
      expect(await db.select().from(users).all()).toMatchObject([{ email: "alice@gmail.com", role: "admin" }]);
    });

    it("does not create the first admin without hd", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      expect((await loginWith(requireHdAdmin)).status).toBe(403);
      expect(await db.select().from(users).all()).toHaveLength(0);
      expect(await db.select().from(sessions).all()).toHaveLength(0);
      expect(warn).toHaveBeenCalledWith("oidc login rejected", { reason: "google_hd_missing", hd: "undefined" });
    });

    it("does not call beforeOidcUserLinkOrCreate when hd is missing", async () => {
      vi.spyOn(console, "warn").mockImplementation(() => {});
      const check = vi.fn<NonNullable<typeof hooks.beforeOidcUserLinkOrCreate>>().mockResolvedValue(true);
      hooks.beforeOidcUserLinkOrCreate = check;
      await invite();
      expect((await loginWith(requireHd)).status).toBe(403);
      expect(check).not.toHaveBeenCalled();
    });

    it("still applies beforeOidcUserLinkOrCreate after the hd check passes", async () => {
      const check = vi.fn<NonNullable<typeof hooks.beforeOidcUserLinkOrCreate>>().mockResolvedValue(false);
      hooks.beforeOidcUserLinkOrCreate = check;
      const invited = await invite();
      idTokenClaims = { ...idTokenClaims, hd: "example.com" };
      expect((await loginWith(requireHd)).status).toBe(403);
      expect(check).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ operation: "link" }));
      expect(await db.select().from(users).where(eq(users.id, invited.id)).get()).toMatchObject({ oidcSubject: null });
    });

    it("does not check hd when unset", async () => {
      const invited = await invite();
      expect((await loginWith(oidcEnv)).status).toBe(303);
      expect(await db.select().from(users).where(eq(users.id, invited.id)).get()).toMatchObject({ oidcSubject: "sub-1" });
    });

    it("rejects only the first association for an invalid value and calls no hook", async () => {
      const error = vi.spyOn(console, "error").mockImplementation(() => {});
      const check = vi.fn<NonNullable<typeof hooks.beforeOidcUserLinkOrCreate>>().mockResolvedValue(true);
      hooks.beforeOidcUserLinkOrCreate = check;
      const invited = await invite();
      idTokenClaims = { ...idTokenClaims, hd: "example.com" };
      const res = await loginWith({ ...oidcEnv, OIDC_REQUIRE_GOOGLE_HD: "TRUE" });
      expect(res.status).toBe(403);
      expect(error).toHaveBeenCalledWith("invalid configuration", { invalid: ["OIDC_REQUIRE_GOOGLE_HD"] });
      expect(check).not.toHaveBeenCalled();
      expect(await db.select().from(users).where(eq(users.id, invited.id)).get()).toMatchObject({ oidcSubject: null });
      expect(await db.select().from(sessions).all()).toHaveLength(0);
    });

    it("signs in a linked user with an invalid value", async () => {
      expect((await loginWith(adminEnv)).status).toBe(303);
      const error = vi.spyOn(console, "error").mockImplementation(() => {});
      const res = await loginWith({ ...adminEnv, OIDC_REQUIRE_GOOGLE_HD: " true" });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/wiki");
      expect(error).not.toHaveBeenCalled();
    });

    it("returns 403 not_invited for an uninvited email with an invalid value", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const error = vi.spyOn(console, "error").mockImplementation(() => {});
      await createUser({ email: "bob@example.com", role: "admin" });
      expect((await loginWith({ ...oidcEnv, OIDC_REQUIRE_GOOGLE_HD: "1" })).status).toBe(403);
      expect(warn).toHaveBeenCalledWith("oidc login rejected", { reason: "not_invited" });
      expect(error).not.toHaveBeenCalled();
    });
  });

  it("calls beforeSessionIssued with the resolved user before the session is issued", async () => {
    const calls: string[] = [];
    hooks.beforeSessionIssued = async ({ userId }) => {
      const row = await workerEnv.DB.prepare("SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?")
        .bind(userId)
        .first<{ count: number }>();
      calls.push(`${userId}:${row?.count}`);
    };
    const res = await loginWith(adminEnv);
    expect(res.status).toBe(303);
    const user = await db.select().from(users).where(eq(users.oidcSubject, "sub-1")).get();
    expect(calls).toEqual([`${user?.id}:0`]);
  });

  it("runs userCreatedStatements with the INSERT of the first admin", async () => {
    hooks.userCreatedStatements = (d1, userId) => [
      d1
        .prepare("INSERT INTO user_notes (user_id, note) SELECT ?1, 'jit' WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)")
        .bind(userId),
    ];
    expect((await loginWith(adminEnv)).status).toBe(303);
    const user = await db.select().from(users).where(eq(users.oidcSubject, "sub-1")).get();
    expect(user?.role).toBe("admin");
    const note = await workerEnv.DB.prepare("SELECT note FROM user_notes WHERE user_id = ?")
      .bind(user?.id ?? "")
      .first<{ note: string }>();
    expect(note?.note).toBe("jit");
    // A linked user signs in again without a new INSERT.
    expect((await loginWith(adminEnv)).status).toBe(303);
    const row = await workerEnv.DB.prepare("SELECT COUNT(*) AS count FROM user_notes").first<{ count: number }>();
    expect(row?.count).toBe(1);
  });

  it("unifies the host for GET and returns 404 for other methods", async () => {
    const res = await send("https://testapp.workers.dev/auth/login?next=/x", { env: oidcEnv });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe(`${OIDC_ORIGIN}/auth/login?next=/x`);
    const setup = await send("https://testapp.workers.dev/auth/setup", { env: oidcEnv });
    expect(setup.status).toBe(302);
    expect(setup.headers.get("Location")).toBe(`${OIDC_ORIGIN}/auth/setup`);
    const post = await send("https://testapp.workers.dev/auth/logout", { method: "POST", env: oidcEnv });
    expect(post.status).toBe(404);
  });
});
