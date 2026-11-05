import {
  getOAuthApi,
  type AuthRequest,
  type OAuthHelpers,
  type OAuthResourceContext,
} from "@cloudflare/workers-oauth-provider";
import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { safeNext } from "../src/auth/redirect.js";
import { issueSession } from "../src/auth/sessions.js";
import { base64UrlEncode } from "../src/auth/tokens.js";
import type { UserRow } from "../src/db/schema.js";
import type { CoreBindings } from "../src/config.js";
import { clock } from "../src/clock.js";
import { completeMcpAuthorization } from "../src/routes/authorize.js";
import { app, CONSENT_DESCRIPTION, core, hooks, mcp, mcpCalls } from "./fixture/src/index.js";
import {
  createUser,
  db,
  login,
  OIDC_ORIGIN,
  oidcEnv,
  ORIGIN,
  PASSWORD,
  resetDb,
  send,
  setCookies,
  type RequestOptions,
} from "./helpers.js";

const REDIRECT_URI = "https://client.example/cb";
const MCP_ACCEPT = "application/json, text/event-stream";

type Cookies = Record<string, string>;

type FlowOptions = {
  origin?: string;
  env?: Partial<CoreBindings>;
  sharedEnv?: Cloudflare.Env;
  redirectUri?: string;
  clientName?: string;
  // An existing client, instead of registering a new one.
  clientId?: string;
};

type TokenResponse = { access_token: string; refresh_token?: string; resource?: string; expires_in: number };

function withDefaults(options: FlowOptions): RequestOptions {
  return { env: options.env, sharedEnv: options.sharedEnv };
}

async function registerClient(options: FlowOptions = {}): Promise<string> {
  const origin = options.origin ?? ORIGIN;
  const res = await send(`${origin}/oauth/register`, {
    ...withDefaults(options),
    json: {
      redirect_uris: [options.redirectUri ?? REDIRECT_URI],
      token_endpoint_auth_method: "none",
      client_name: options.clientName ?? "Test client",
    },
  });
  expect(res.status).toBe(201);
  const body = (await res.json()) as { client_id: string };
  return body.client_id;
}

async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: base64UrlEncode(new Uint8Array(digest)) };
}

function authorizeUrl(origin: string, clientId: string, challenge: string, redirectUri = REDIRECT_URI): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: "mcp",
    state: "state-123",
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: `${origin}/mcp`,
  });
  return `${origin}/authorize?${params}`;
}

type Consent = { html: string; handle: string; cookies: Cookies };

async function openConsent(
  sessionCookies: Cookies,
  options: FlowOptions = {},
): Promise<Consent & { clientId: string; verifier: string }> {
  const origin = options.origin ?? ORIGIN;
  const clientId = options.clientId ?? (await registerClient(options));
  const { verifier, challenge } = await pkce();
  const res = await send(authorizeUrl(origin, clientId, challenge, options.redirectUri), {
    ...withDefaults(options),
    cookies: sessionCookies,
  });
  expect(res.status).toBe(200);
  const html = await res.text();
  const handle = /name="handle" value="([^"]+)"/.exec(html)?.[1];
  if (!handle) throw new Error(`handle not found: ${html}`);
  const cookies: Cookies = { ...sessionCookies };
  for (const [name, cookie] of Object.entries(setCookies(res))) cookies[name] = cookie.value;
  return { html, handle, cookies, clientId, verifier };
}

// Runs DCR, PKCE, the consent page and the token request, and returns the token response.
async function authorizeClient(sessionCookies: Cookies, options: FlowOptions = {}): Promise<TokenResponse> {
  const origin = options.origin ?? ORIGIN;
  const consent = await openConsent(sessionCookies, options);
  const approved = await send(`${origin}/authorize`, {
    ...withDefaults(options),
    cookies: consent.cookies,
    form: { handle: consent.handle, decision: "approve" },
  });
  expect(approved.status).toBe(302);
  const location = new URL(approved.headers.get("Location") ?? "");
  const code = location.searchParams.get("code");
  if (!code) throw new Error(`code not found: ${location.href}`);

  const res = await send(`${origin}/oauth/token`, {
    ...withDefaults(options),
    form: {
      grant_type: "authorization_code",
      code,
      redirect_uri: options.redirectUri ?? REDIRECT_URI,
      client_id: consent.clientId,
      code_verifier: consent.verifier,
    },
  });
  expect(res.status).toBe(200);
  return (await res.json()) as TokenResponse;
}

async function mcpRequest(
  token: string,
  method: string,
  params: Record<string, unknown> = {},
  options: { origin?: string; env?: Partial<CoreBindings>; sharedEnv?: Cloudflare.Env } = {},
): Promise<Response> {
  return send(`${options.origin ?? ORIGIN}/mcp`, {
    env: options.env,
    sharedEnv: options.sharedEnv,
    headers: { Authorization: `Bearer ${token}`, Accept: MCP_ACCEPT },
    json: { jsonrpc: "2.0", id: 1, method, params },
  });
}

// The params of initialize, which needs no tools. Used to check whether a token is accepted.
const INITIALIZE_PARAMS = {
  protocolVersion: "2025-06-18",
  capabilities: {},
  clientInfo: { name: "test", version: "1.0.0" },
};

function mcpInitialize(
  token: string,
  options: { origin?: string; env?: Partial<CoreBindings>; sharedEnv?: Cloudflare.Env } = {},
): Promise<Response> {
  return mcpRequest(token, "initialize", INITIALIZE_PARAMS, options);
}

// The token was accepted: HTTP 200 with the result of initialize from this server.
async function expectMcpOk(res: Response): Promise<void> {
  expect(res.status).toBe(200);
  const body = (await res.json()) as { result?: { serverInfo?: { name?: string } } };
  expect(body.result?.serverInfo?.name).toBe("testapp");
}

async function oidcSessionCookies(user: UserRow): Promise<Cookies> {
  const now = Date.now();
  const session = await issueSession(db, user.id, "oidc", now);
  const at = await core.signAccessToken({ sub: user.id, sid: session.sessionId }, env.JWT_SECRET ?? "", now);
  return { "__Host-testapp_at": at, "__Host-testapp_rt": session.refreshToken };
}

function oauthApi(origin: string, overrides: Partial<CoreBindings> = {}) {
  return getOAuthApi(core.buildOAuthProviderOptions(origin, app), { ...env, ...overrides });
}

let admin: UserRow;
let member: UserRow;
let adminCookies: Cookies;
let memberCookies: Cookies;

beforeEach(async () => {
  await resetDb();
  admin = await createUser({ email: "admin@example.com", role: "admin" });
  member = await createUser({ email: "member@example.com" });
  adminCookies = await login(admin.email);
  memberCookies = await login(member.email);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("discovery", () => {
  it("answers /mcp without a token with 401 and a challenge", async () => {
    const res = await send("/mcp", { json: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(res.status).toBe(401);
    const challenge = res.headers.get("WWW-Authenticate") ?? "";
    expect(challenge).toContain(`resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp"`);
  });

  it("publishes the protected resource metadata", async () => {
    const res = await send("/.well-known/oauth-protected-resource/mcp");
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.resource).toBe(`${ORIGIN}/mcp`);
    expect(body.authorization_servers).toEqual([ORIGIN]);
    expect(body.scopes_supported).toEqual(["mcp"]);
  });

  it("publishes the authorization server metadata", async () => {
    const res = await send("/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.issuer).toBe(ORIGIN);
    expect(body.authorization_endpoint).toBe(`${ORIGIN}/authorize`);
    expect(body.token_endpoint).toBe(`${ORIGIN}/oauth/token`);
    expect(body.registration_endpoint).toBe(`${ORIGIN}/oauth/register`);
    expect(body.scopes_supported).toEqual(["mcp"]);
    expect(body.protected_resources).toEqual([`${ORIGIN}/mcp`]);
    expect(body.resource).toBeUndefined();
  });
});

describe("GET /authorize", () => {
  it("sends a signed-out user to the login page and back", async () => {
    const clientId = await registerClient();
    const { challenge } = await pkce();
    const url = new URL(authorizeUrl(ORIGIN, clientId, challenge));
    const res = await send(url.href);
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("Location") ?? "", ORIGIN);
    expect(location.pathname).toBe("/auth/login");
    const next = location.searchParams.get("next");
    expect(next).toBe(`${url.pathname}${url.search}`);
    expect(safeNext(next, ORIGIN)).toBe(`${url.pathname}${url.search}`);

    // With a refresh token, GET /auth/login renews the session and returns to the same URL.
    const back = await send(`${location.pathname}${location.search}`, {
      cookies: { "__Host-testapp_rt": memberCookies["__Host-testapp_rt"] ?? "" },
    });
    expect(back.status).toBe(302);
    expect(back.headers.get("Location")).toBe(`${url.pathname}${url.search}`);
  });

  it("renders an invalid request locally without a redirect", async () => {
    const res = await send("/authorize?response_type=code&client_id=missing", { cookies: memberCookies });
    expect(res.status).toBe(400);
    expect(res.headers.get("Location")).toBeNull();
  });

  it("answers HEAD and prefetches with 204 before reading the request", async () => {
    const clientId = await registerClient();
    const { challenge } = await pkce();
    const url = authorizeUrl(ORIGIN, clientId, challenge);
    const head = await send(url, { method: "HEAD", cookies: memberCookies });
    expect(head.status).toBe(204);
    expect(head.headers.getSetCookie()).toEqual([]);
    const prefetch = await send(url, { cookies: memberCookies, headers: { "Sec-Purpose": "prefetch" } });
    expect(prefetch.status).toBe(204);
  });

  it("shows the client, the redirect host and the user, escaped and not frameable", async () => {
    const consent = await openConsent(memberCookies, { clientName: "<script>alert(1)</script>" });
    expect(consent.html).not.toContain("<script>alert(1)</script>");
    expect(consent.html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(consent.html).toContain("このアプリの名前は確認されていません");
    expect(consent.html).toContain("client.example");
    expect(consent.html).toContain(member.email);
    expect(consent.html).not.toContain("このパソコン上のアプリ");
    expect(consent.html).toContain(CONSENT_DESCRIPTION);
    const res = await send(authorizeUrl(ORIGIN, consent.clientId, (await pkce()).challenge), {
      cookies: memberCookies,
    });
    expect(res.headers.get("Content-Security-Policy")).toBe("frame-ancestors 'none'");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  it("warns when the redirect goes to a loopback address", async () => {
    const consent = await openConsent(memberCookies, { redirectUri: "http://127.0.0.1:33418/callback" });
    expect(consent.html).toContain("127.0.0.1");
    expect(consent.html).toContain("このパソコン上のアプリに接続を渡します");
  });
});

describe("POST /authorize", () => {
  it("redirects with access_denied when the user declines", async () => {
    const consent = await openConsent(memberCookies);
    const res = await send("/authorize", {
      cookies: consent.cookies,
      form: { handle: consent.handle, decision: "deny" },
    });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("Location") ?? "");
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("state")).toBe("state-123");
    expect(await oauthApi(ORIGIN).listUserGrants(member.id)).toMatchObject({ items: [] });
  });

  it("rejects a handle without the consent cookie", async () => {
    const consent = await openConsent(memberCookies);
    const res = await send("/authorize", {
      cookies: memberCookies,
      form: { handle: consent.handle, decision: "approve" },
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("画面の有効期限が切れたか");
  });

  it("requires the web session", async () => {
    const consent = await openConsent(memberCookies);
    const { "__Host-testapp_at": _at, ...withoutSession } = consent.cookies;
    const res = await send("/authorize", { cookies: withoutSession, form: { handle: consent.handle, decision: "approve" } });
    expect(res.status).toBe(401);
  });

  it("rejects a cross-site form post", async () => {
    const consent = await openConsent(memberCookies);
    const res = await send("/authorize", {
      cookies: consent.cookies,
      form: { handle: consent.handle, decision: "approve" },
      origin: "https://evil.example",
    });
    expect(res.status).toBe(403);
  });
});

describe("MCP", () => {
  it("initializes with a token from the OAuth flow", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    await expectMcpOk(await mcpInitialize(access_token));
  });

  it("returns 401 once the user is deleted", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    await expectMcpOk(await mcpInitialize(access_token));
    await env.DB.batch([
      env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(member.id),
      env.DB.prepare("DELETE FROM users WHERE id = ?").bind(member.id),
    ]);
    const res = await mcpInitialize(access_token);
    expect(res.status).toBe(401);
    expect(await res.text()).toBe("");
    expect(res.headers.get("WWW-Authenticate")).toBe(
      `Bearer error="invalid_token", resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp"`,
    );
  });

  it("answers GET and DELETE with 405", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    for (const method of ["GET", "DELETE"]) {
      const res = await send("/mcp", {
        method,
        headers: { Authorization: `Bearer ${access_token}`, Accept: MCP_ACCEPT },
      });
      expect(res.status).toBe(405);
      expect(res.headers.get("Allow")).toBe("POST");
    }
  });

  it("answers a token without the mcp scope with 403", async () => {
    // Clients cannot get such a token from this server (consent always grants mcp), so the
    // handler is called directly with the context OAuthProvider would pass.
    const ctx = Object.assign(createExecutionContext(), {
      props: { userId: member.id, authMode: "password", authorizedAt: Date.now() },
      auth: { token: "t", audience: `${ORIGIN}/mcp`, scope: [] },
    }) as unknown as OAuthResourceContext<unknown>;
    const request = new Request(`${ORIGIN}/mcp`, {
      method: "POST",
      headers: { Accept: MCP_ACCEPT, "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    const res = await core.mcpHandler.fetch(request, env, ctx);
    expect(res.status).toBe(403);
    expect(res.headers.get("WWW-Authenticate")).toContain('error="insufficient_scope"');
  });
});

describe("revoking sessions", () => {
  async function expectRevoked(token: string, userId: string) {
    expect((await mcpInitialize(token)).status).toBe(401);
    expect((await oauthApi(ORIGIN).listUserGrants(userId)).items).toEqual([]);
  }

  it("revokes MCP grants with POST /api/v1/users/:id/revoke-sessions", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    await expectMcpOk(await mcpInitialize(access_token));
    const res = await send(`/api/v1/users/${member.id}/revoke-sessions`, { method: "POST", cookies: adminCookies });
    expect(res.status).toBe(204);
    await expectRevoked(access_token, member.id);
  });

  it("revokes MCP grants when an admin resets the password", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    const res = await send(`/api/v1/users/${member.id}/password`, {
      cookies: adminCookies,
      json: { password: "a brand new password" },
    });
    expect(res.status).toBe(204);
    await expectRevoked(access_token, member.id);
  });

  it("revokes MCP grants when the user changes the password", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    const res = await send("/api/v1/me/password", {
      cookies: memberCookies,
      json: { current_password: PASSWORD, new_password: "a brand new password" },
    });
    expect(res.status).toBe(204);
    await expectRevoked(access_token, member.id);
  });

  it("revokes MCP grants when an admin deletes the user", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    expect((await oauthApi(ORIGIN).listUserGrants(member.id)).items).toHaveLength(1);
    const res = await send(`/api/v1/users/${member.id}`, { method: "DELETE", cookies: adminCookies });
    expect(res.status).toBe(204);
    await expectRevoked(access_token, member.id);
  });

  it("keeps MCP grants when the web session logs out", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    expect((await send("/auth/logout", { method: "POST", cookies: memberCookies })).status).toBe(200);
    await expectMcpOk(await mcpInitialize(access_token));
  });
});

describe("grant lifetime", () => {
  it("is 30 days in password mode", async () => {
    const before = Math.floor(Date.now() / 1000);
    const token = await authorizeClient(memberCookies);
    const after = Math.floor(Date.now() / 1000);
    expect(token.refresh_token).toBeDefined();
    const { items } = await oauthApi(ORIGIN).listUserGrants(member.id);
    expect(items).toHaveLength(1);
    const expiresAt = items[0]?.expiresAt ?? 0;
    expect(expiresAt).toBeGreaterThanOrEqual(before + 2_592_000);
    expect(expiresAt).toBeLessThanOrEqual(after + 2_592_000);
  });

  it("is 24 hours in oidc mode", async () => {
    const cookies = await oidcSessionCookies(member);
    const before = Math.floor(Date.now() / 1000);
    await authorizeClient(cookies, { origin: OIDC_ORIGIN, env: oidcEnv });
    const after = Math.floor(Date.now() / 1000);
    const { items } = await oauthApi(OIDC_ORIGIN, oidcEnv).listUserGrants(member.id);
    expect(items).toHaveLength(1);
    const expiresAt = items[0]?.expiresAt ?? 0;
    expect(expiresAt).toBeGreaterThanOrEqual(before + 86_400);
    expect(expiresAt).toBeLessThanOrEqual(after + 86_400);
  });
});

describe("origins and configuration", () => {
  it("returns 401 for a token issued in another AUTH_MODE", async () => {
    // Password mode on the host that later becomes APP_ORIGIN.
    const { access_token } = await authorizeClient(memberCookies, { origin: OIDC_ORIGIN });
    await expectMcpOk(await mcpInitialize(access_token, { origin: OIDC_ORIGIN }));
    const res = await mcpInitialize(access_token, { origin: OIDC_ORIGIN, env: oidcEnv });
    expect(res.status).toBe(401);
  });

  it("returns 404 for OAuth paths on hosts other than APP_ORIGIN in oidc mode", async () => {
    for (const path of ["/mcp", "/authorize", "/oauth/token", "/.well-known/oauth-authorization-server"]) {
      const res = await send(`https://other.example.com${path}`, { env: oidcEnv });
      expect(res.status).toBe(404);
    }
    const metadata = await send(`${OIDC_ORIGIN}/.well-known/oauth-authorization-server`, { env: oidcEnv });
    expect(metadata.status).toBe(200);
    // Pages still go through unifyHost.
    const page = await send("https://other.example.com/auth/setup", { env: oidcEnv });
    expect(page.status).toBe(302);
    expect(page.headers.get("Location")).toBe(`${OIDC_ORIGIN}/auth/setup`);
  });

  it("serves pages but not OAuth on a plain http host that is not loopback", async () => {
    const me = await send("http://wiki.example.com/api/v1/me", { cookies: memberCookies });
    expect(me.status).toBe(200);
    expect(await me.text()).toContain(member.email);
    expect((await send("http://wiki.example.com/mcp", { json: {} })).status).toBe(404);
    expect((await send("http://wiki.example.com/authorize")).status).toBe(404);
  });

  it("serves OAuth on loopback http", async () => {
    const res = await send("http://localhost:8787/.well-known/oauth-protected-resource/mcp");
    expect(res.status).toBe(200);
    expect(((await res.json()) as { resource: string }).resource).toBe("http://localhost:8787/mcp");
  });

  it("returns 500 for every path when the configuration is invalid", async () => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    for (const path of ["/mcp", "/.well-known/oauth-authorization-server", "/oauth/token", "/authorize"]) {
      const res = await send(path, { env: { JWT_SECRET: "short" } });
      expect(res.status).toBe(500);
    }
    expect(errorLog).toHaveBeenCalledWith("invalid configuration", { invalid: ["JWT_SECRET"] });
  });

  it("uses the helpers of the request's origin when the env object is reused", async () => {
    const shared: Cloudflare.Env = { ...env };
    const other = "https://second.app.test";
    const first = await authorizeClient(memberCookies, { sharedEnv: shared });
    const second = await authorizeClient(memberCookies, { origin: other, sharedEnv: shared });
    expect(first.resource).toBe(`${ORIGIN}/mcp`);
    expect(second.resource).toBe(`${other}/mcp`);
    expect(shared.OAUTH_PROVIDER).toBeUndefined();
    await expectMcpOk(await mcpInitialize(second.access_token, { origin: other, sharedEnv: shared }));
    // Tokens are bound to their origin's resource.
    expect((await mcpInitialize(first.access_token, { origin: other, sharedEnv: shared })).status).toBe(401);
  });
});

describe("reauthorization", () => {
  it("revokes the earlier grant of the same client and redirect URI", async () => {
    const clientId = await registerClient();
    const first = await authorizeClient(memberCookies, { clientId });
    const second = await authorizeClient(memberCookies, { clientId });
    expect((await mcpInitialize(first.access_token)).status).toBe(401);
    await expectMcpOk(await mcpInitialize(second.access_token));
    expect((await oauthApi(ORIGIN).listUserGrants(member.id)).items).toHaveLength(1);
  });

  it("keeps the grant of another client", async () => {
    const clientId = await registerClient();
    const otherClientId = await registerClient({ clientName: "Other client" });
    const other = await authorizeClient(memberCookies, { clientId: otherClientId });
    await authorizeClient(memberCookies, { clientId });
    await authorizeClient(memberCookies, { clientId });
    await expectMcpOk(await mcpInitialize(other.access_token));
    const grants = (await oauthApi(ORIGIN).listUserGrants(member.id)).items;
    expect(grants.map((grant) => grant.clientId).sort()).toEqual([clientId, otherClientId].sort());
  });

  it("keeps the existing grant when the user declines", async () => {
    const clientId = await registerClient();
    const first = await authorizeClient(memberCookies, { clientId });
    const consent = await openConsent(memberCookies, { clientId });
    const denied = await send("/authorize", { cookies: consent.cookies, form: { handle: consent.handle, decision: "deny" } });
    expect(denied.status).toBe(302);
    await expectMcpOk(await mcpInitialize(first.access_token));
    expect((await oauthApi(ORIGIN).listUserGrants(member.id)).items).toHaveLength(1);
  });
});

describe("mcp_revoked_at", () => {
  async function readMcpRevokedAt(userId: string): Promise<number | null> {
    const row = await env.DB.prepare("SELECT mcp_revoked_at FROM users WHERE id = ?")
      .bind(userId)
      .first<{ mcp_revoked_at: number | null }>();
    return row?.mcp_revoked_at ?? null;
  }

  it("rejects a token authorized at or before it, even when the grant is still in KV", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    await expectMcpOk(await mcpInitialize(access_token));
    await env.DB.prepare("UPDATE users SET mcp_revoked_at = ? WHERE id = ?").bind(Date.now(), member.id).run();
    expect((await oauthApi(ORIGIN).listUserGrants(member.id)).items).toHaveLength(1);
    expect((await mcpInitialize(access_token)).status).toBe(401);
  });

  it("accepts a token authorized after it", async () => {
    await env.DB.prepare("UPDATE users SET mcp_revoked_at = ? WHERE id = ?").bind(Date.now() - 1, member.id).run();
    const { access_token } = await authorizeClient(memberCookies);
    await expectMcpOk(await mcpInitialize(access_token));
  });

  it("is set when the user changes the password", async () => {
    const before = Date.now();
    const res = await send("/api/v1/me/password", {
      cookies: memberCookies,
      json: { current_password: PASSWORD, new_password: "a brand new password" },
    });
    expect(res.status).toBe(204);
    expect(await readMcpRevokedAt(member.id)).toBeGreaterThanOrEqual(before);
  });

  it("is set when an admin resets the password", async () => {
    const before = Date.now();
    const res = await send(`/api/v1/users/${member.id}/password`, {
      cookies: adminCookies,
      json: { password: "a brand new password" },
    });
    expect(res.status).toBe(204);
    expect(await readMcpRevokedAt(member.id)).toBeGreaterThanOrEqual(before);
    expect(await readMcpRevokedAt(admin.id)).toBeNull();
  });

  it("is set when an admin revokes the sessions", async () => {
    const before = Date.now();
    const res = await send(`/api/v1/users/${member.id}/revoke-sessions`, { method: "POST", cookies: adminCookies });
    expect(res.status).toBe(204);
    expect(await readMcpRevokedAt(member.id)).toBeGreaterThanOrEqual(before);
  });

  it("is set without OAUTH_PROVIDER, on a host that cannot serve OAuth", async () => {
    const res = await send(`http://wiki.example.com/api/v1/users/${member.id}/revoke-sessions`, {
      method: "POST",
      cookies: adminCookies,
    });
    expect(res.status).toBe(204);
    expect(await readMcpRevokedAt(member.id)).not.toBeNull();
  });
});

describe("hooks around MCP", () => {
  async function callWhoami(token: string): Promise<Response> {
    return mcpRequest(token, "tools/call", { name: "whoami", arguments: {} });
  }

  it("still revokes the grants when afterUserDeleted throws", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { access_token } = await authorizeClient(memberCookies);
    hooks.afterUserDeleted = async () => {
      throw new Error("storage is down");
    };
    const res = await send(`/api/v1/users/${member.id}`, { method: "DELETE", cookies: adminCookies });
    expect(res.status).toBe(204);
    expect((await mcpInitialize(access_token)).status).toBe(401);
    expect((await oauthApi(ORIGIN).listUserGrants(member.id)).items).toEqual([]);
  });

  it("rejects the token with 401 when parseProps returns null", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    await expectMcpOk(await mcpInitialize(access_token));
    mcp.parseProps = () => null;
    const res = await mcpInitialize(access_token);
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
  });

  it("keeps the base fields when app props try to set userId", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    mcp.parseProps = () => ({ noteId: "note-1", userId: admin.id }) as unknown as { noteId: string };
    const res = await callWhoami(access_token);
    expect(res.status).toBe(200);
    expect(mcpCalls).toHaveLength(1);
    expect(mcpCalls[0]?.props).toMatchObject({ noteId: "note-1", userId: member.id, authMode: "password" });
    const body = (await res.json()) as { result: { content: { text: string }[] } };
    expect(JSON.parse(body.result.content[0]?.text ?? "")).toMatchObject({ email: member.email });
  });

  it("returns the Response of checkRequest as is", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    mcp.checkRequest = ({ invalidToken, user }) => (user.id === member.id ? invalidToken() : { ok: true, extra: undefined });
    const res = await mcpInitialize(access_token);
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe(
      `Bearer error="invalid_token", resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp"`,
    );
    mcp.checkRequest = () => new Response("no bot", { status: 403 });
    expect((await mcpInitialize(access_token)).status).toBe(403);
    expect(mcpCalls).toEqual([]);
  });

  it("passes the extra of checkRequest to register", async () => {
    const { access_token } = await authorizeClient(memberCookies);
    mcp.checkRequest = async ({ props }) => ({ ok: true, extra: { label: `checked ${props.userId}` } });
    const res = await callWhoami(access_token);
    expect(res.status).toBe(200);
    expect(mcpCalls[0]?.extra).toEqual({ label: `checked ${member.id}` });
    const body = (await res.json()) as { result: { content: { text: string }[] } };
    expect(JSON.parse(body.result.content[0]?.text ?? "")).toEqual({
      email: member.email,
      extra: { label: `checked ${member.id}` },
    });
  });
});

describe("completeMcpAuthorization", () => {
  it("rejects a token whose authorizedAt was taken before a mcp_revoked_at written during the request", async () => {
    const consent = await openConsent(memberCookies);
    const authorizedAt = Date.now() - 1000;
    // The first clock reading of POST /authorize is authorizedAt.
    vi.spyOn(clock, "now").mockReturnValueOnce(authorizedAt);
    const approved = await send("/authorize", {
      cookies: consent.cookies,
      form: { handle: consent.handle, decision: "approve" },
    });
    expect(approved.status).toBe(302);
    // A revocation recorded after authorizedAt, while the authorization was running.
    await env.DB.prepare("UPDATE users SET mcp_revoked_at = ? WHERE id = ?").bind(authorizedAt + 1, member.id).run();
    const code = new URL(approved.headers.get("Location") ?? "").searchParams.get("code") ?? "";
    const token = await send("/oauth/token", {
      form: {
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: consent.clientId,
        code_verifier: consent.verifier,
      },
    });
    expect(token.status).toBe(200);
    const { access_token } = (await token.json()) as TokenResponse;
    expect((await mcpInitialize(access_token)).status).toBe(401);
  });

  it("writes the base fields last and passes the options through", async () => {
    let received: Record<string, unknown> | undefined;
    const oauth = {
      completeAuthorization: async (options: Record<string, unknown>) => {
        received = options;
        return { redirectTo: "https://client.example/cb?code=x" };
      },
    } as unknown as OAuthHelpers;
    const request = { clientId: "c" } as unknown as AuthRequest;
    const result = await completeMcpAuthorization(oauth, {
      request,
      userId: "user-1",
      authMode: "oidc",
      authorizedAt: 123,
      props: { connectionId: "conn-1", userId: "evil" } as unknown as { connectionId: string },
      revokeExistingGrants: false,
    });
    expect(result).toEqual({ redirectTo: "https://client.example/cb?code=x" });
    expect(received).toEqual({
      request,
      userId: "user-1",
      metadata: {},
      scope: ["mcp"],
      props: { connectionId: "conn-1", userId: "user-1", authMode: "oidc", authorizedAt: 123 },
      revokeExistingGrants: false,
    });
  });
});
