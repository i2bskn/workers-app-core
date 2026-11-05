import { eq } from "drizzle-orm";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { env as workerEnv } from "cloudflare:workers";
import { evaluateIdTokenClaims, isEmailVerified } from "../src/auth/oidc.js";
import { base64UrlEncode } from "../src/auth/tokens.js";
import { resolveOidcUser, type OidcIdentity } from "../src/auth/users.js";
import { users } from "../src/db/schema.js";
import { loadConfig, type CoreBindings } from "../src/config.js";
import {
  createUser,
  db,
  OIDC_ALLOWED_EMAILS,
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

describe("resolveOidcUser", () => {
  it("creates the first user as admin and later users as members (JIT)", async () => {
    const first = await resolveOidcUser(db, identity(), NOW);
    const second = await resolveOidcUser(db, identity({ subject: "sub-2", email: "bob@example.com" }), NOW);
    expect(first).toMatchObject({ ok: true, user: { role: "admin", email: "alice@example.com", name: "Alice" } });
    expect(second).toMatchObject({ ok: true, user: { role: "member", oidcSubject: "sub-2" } });
  });

  it("creates only one admin for concurrent first logins", async () => {
    const results = await Promise.all([
      resolveOidcUser(db, identity(), NOW),
      resolveOidcUser(db, identity({ subject: "sub-2", email: "bob@example.com" }), NOW),
      resolveOidcUser(db, identity({ subject: "sub-3", email: "carol@example.com" }), NOW),
    ]);
    expect(results.every((r) => r.ok)).toBe(true);
    const all = await db.select().from(users).all();
    expect(all.filter((u) => u.role === "admin")).toHaveLength(1);
  });

  it("finds a linked user by issuer and subject and updates the email", async () => {
    const created = await resolveOidcUser(db, identity(), NOW);
    const again = await resolveOidcUser(db, identity({ email: "alice@new.example.com" }), NOW + 1);
    expect(again.ok && again.user.id).toBe(created.ok && created.user.id);
    const row = await db.select().from(users).where(eq(users.oidcSubject, "sub-1")).get();
    expect(row?.email).toBe("alice@new.example.com");
  });

  it("keeps the old email when the new one belongs to another user", async () => {
    await resolveOidcUser(db, identity(), NOW);
    await createUser({ email: "taken@example.com" });
    const again = await resolveOidcUser(db, identity({ email: "taken@example.com" }), NOW + 1);
    expect(again).toMatchObject({ ok: true, user: { email: "alice@example.com", oidcSubject: "sub-1" } });
  });

  it("links an existing user with the same email and no subject", async () => {
    const existing = await createUser({ email: "alice@example.com", role: "admin" });
    const result = await resolveOidcUser(db, identity(), NOW);
    expect(result).toMatchObject({ ok: true, user: { id: existing.id, oidcIssuer: ISSUER, oidcSubject: "sub-1" } });
    expect(await db.select().from(users).all()).toHaveLength(1);
  });

  it("rejects an email that is linked to a different issuer or subject", async () => {
    await resolveOidcUser(db, identity(), NOW);
    expect(await resolveOidcUser(db, identity({ subject: "other-sub" }), NOW)).toEqual({ ok: false, reason: "conflict" });
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

  it("evaluates email, email_verified and the allowlist", () => {
    const opts = (allowedEmails: string) => ({ allowedEmails, requireEmailVerified: true });
    const base = { email: " Alice@Example.com ", email_verified: true, name: " Alice " };
    // An empty allowlist allows no one.
    expect(evaluateIdTokenClaims(base, opts(""))).toEqual({ ok: false, reason: "not_allowed" });
    expect(evaluateIdTokenClaims({ ...base, name: "a".repeat(101) }, opts(""))).toEqual({ ok: false, reason: "not_allowed" });
    const allowed = opts(OIDC_ALLOWED_EMAILS);
    expect(evaluateIdTokenClaims(base, allowed)).toEqual({ ok: true, email: "alice@example.com", name: "Alice" });
    expect(evaluateIdTokenClaims({ ...base, name: "a".repeat(101) }, allowed)).toMatchObject({ ok: true, name: null });
    expect(evaluateIdTokenClaims(base, opts("*"))).toEqual({ ok: true, email: "alice@example.com", name: "Alice" });
    expect(evaluateIdTokenClaims({ email_verified: true }, opts(""))).toEqual({ ok: false, reason: "invalid_email" });
    expect(evaluateIdTokenClaims({ ...base, email: "bad" }, opts(""))).toEqual({ ok: false, reason: "invalid_email" });
    expect(evaluateIdTokenClaims({ ...base, email_verified: false }, opts(""))).toEqual({
      ok: false,
      reason: "email_not_verified",
    });
    expect(evaluateIdTokenClaims({ ...base, email_verified: "true" }, opts(""))).toEqual({
      ok: false,
      reason: "email_not_verified",
    });
    expect(evaluateIdTokenClaims({ email: base.email }, opts(""))).toEqual({ ok: false, reason: "email_not_verified" });
    expect(evaluateIdTokenClaims(base, opts("other.com"))).toEqual({ ok: false, reason: "not_allowed" });
    expect(evaluateIdTokenClaims(base, opts("example.com"))).toMatchObject({ ok: true });
  });

  it("evaluates claims when email_verified is not required", () => {
    const opts = (allowedEmails: string) => ({ allowedEmails, requireEmailVerified: false });
    const base = { email: " Alice@Example.com ", name: " Alice " };
    // An empty allowlist allows no one.
    expect(evaluateIdTokenClaims(base, opts(""))).toEqual({ ok: false, reason: "not_allowed" });
    expect(evaluateIdTokenClaims({ ...base, email_verified: true }, opts(""))).toEqual({ ok: false, reason: "not_allowed" });
    const allowed = opts(OIDC_ALLOWED_EMAILS);
    expect(evaluateIdTokenClaims(base, allowed)).toEqual({ ok: true, email: "alice@example.com", name: "Alice" });
    expect(evaluateIdTokenClaims({ ...base, email_verified: true }, allowed)).toMatchObject({ ok: true });
    for (const value of [false, "true", null]) {
      expect(evaluateIdTokenClaims({ ...base, email_verified: value }, opts(""))).toEqual({
        ok: false,
        reason: "email_not_verified",
      });
    }
    expect(evaluateIdTokenClaims({ ...base, email: "bad" }, opts(""))).toEqual({ ok: false, reason: "invalid_email" });
    expect(evaluateIdTokenClaims({ ...base, email: "bad", email_verified: false }, opts(""))).toEqual({
      ok: false,
      reason: "invalid_email",
    });
    expect(evaluateIdTokenClaims(base, opts("other.com"))).toEqual({ ok: false, reason: "not_allowed" });
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

  async function startLogin(next = "/wiki", env: Partial<CoreBindings> = oidcEnv) {
    const res = await send(`${OIDC_ORIGIN}/auth/login?next=${encodeURIComponent(next)}`, { env });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("Location") ?? "");
    pendingNonce = location.searchParams.get("nonce") ?? "";
    const oidcCookie = setCookies(res)["__Host-testapp_oidc"];
    expect(oidcCookie?.maxAge).toBe(600);
    return { location, oidcCookie: oidcCookie?.value ?? "" };
  }

  function callback(query: string, oidcCookie?: string, env: Partial<CoreBindings> = oidcEnv) {
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
    const env = { ...oidcEnv, OIDC_REQUIRE_EMAIL_VERIFIED: "false" };
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

  it("returns 403 for emails outside the allowlist", async () => {
    const env = { ...oidcEnv, ALLOWED_EMAILS: "other.com" };
    const login = await send(`${OIDC_ORIGIN}/auth/login`, { env });
    const location = new URL(login.headers.get("Location") ?? "");
    pendingNonce = location.searchParams.get("nonce") ?? "";
    const oidcCookie = setCookies(login)["__Host-testapp_oidc"]?.value ?? "";
    const res = await send(`${OIDC_ORIGIN}/auth/oidc/callback?code=abc&state=${location.searchParams.get("state")}`, {
      env,
      cookies: { "__Host-testapp_oidc": oidcCookie },
    });
    expect(res.status).toBe(403);
    expect(await db.select().from(users).all()).toHaveLength(0);
  });

  async function loginWith(env: Partial<CoreBindings>) {
    const { location, oidcCookie } = await startLogin("/wiki", env);
    return callback(`code=abc&state=${location.searchParams.get("state")}`, oidcCookie, env);
  }

  it("returns 403 and creates nothing when ALLOWED_EMAILS is empty", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const res = await loginWith({ ...oidcEnv, ALLOWED_EMAILS: "" });
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("このアカウントではログインできません");
    expect(await db.select().from(users).all()).toHaveLength(0);
    expect(warn).toHaveBeenCalledWith("oidc login rejected", { reason: "allowlist_empty" });
  });

  it("treats an ALLOWED_EMAILS of only commas and spaces as empty", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const res = await loginWith({ ...oidcEnv, ALLOWED_EMAILS: " , ," });
    expect(res.status).toBe(403);
    expect(await db.select().from(users).all()).toHaveLength(0);
    expect(warn).toHaveBeenCalledWith("oidc login rejected", { reason: "allowlist_empty" });
  });

  it("logs not_allowed for an email outside a non-empty allowlist", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const res = await loginWith({ ...oidcEnv, ALLOWED_EMAILS: "other.com" });
    expect(res.status).toBe(403);
    expect(warn).toHaveBeenCalledWith("oidc login rejected", { reason: "not_allowed" });
  });

  it.each([["*"], ["*,example.com"]])("signs in any email with ALLOWED_EMAILS=%j", async (allowedEmails) => {
    idTokenClaims = { ...idTokenClaims, email: "alice@outside.test" };
    const res = await loginWith({ ...oidcEnv, ALLOWED_EMAILS: allowedEmails });
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/wiki");
    const user = await db.select().from(users).where(eq(users.oidcSubject, "sub-1")).get();
    expect(user?.email).toBe("alice@outside.test");
  });

  it("calls beforeSessionIssued with the resolved user before the session is issued", async () => {
    const calls: string[] = [];
    hooks.beforeSessionIssued = async ({ userId }) => {
      const row = await workerEnv.DB.prepare("SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?")
        .bind(userId)
        .first<{ count: number }>();
      calls.push(`${userId}:${row?.count}`);
    };
    const res = await loginWith(oidcEnv);
    expect(res.status).toBe(303);
    const user = await db.select().from(users).where(eq(users.oidcSubject, "sub-1")).get();
    expect(calls).toEqual([`${user?.id}:0`]);
  });

  it("runs userCreatedStatements with the JIT INSERT", async () => {
    hooks.userCreatedStatements = (d1, userId) => [
      d1
        .prepare("INSERT INTO user_notes (user_id, note) SELECT ?1, 'jit' WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)")
        .bind(userId),
    ];
    expect((await loginWith(oidcEnv)).status).toBe(303);
    const user = await db.select().from(users).where(eq(users.oidcSubject, "sub-1")).get();
    const note = await workerEnv.DB.prepare("SELECT note FROM user_notes WHERE user_id = ?")
      .bind(user?.id ?? "")
      .first<{ note: string }>();
    expect(note?.note).toBe("jit");
    // A linked user signs in again without a new INSERT.
    expect((await loginWith(oidcEnv)).status).toBe(303);
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
