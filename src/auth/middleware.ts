import type { Context, Env, MiddlewareHandler } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { DrizzleQueryError, eq } from "drizzle-orm";
import type { ApiError } from "../api-types.js";
import type { BrandNames, PageMarkup } from "../brand.js";
import { clock } from "../clock.js";
import { loadConfig, type AppEnv, type AuthMode } from "../config.js";
import { createDb } from "../db/client.js";
import { sessions, users, type UserRow } from "../db/schema.js";
import { getAccessCookie } from "./cookies.js";
import { verifyAccessToken } from "./tokens.js";

// The environment the package's own routes and middleware are written against.
export type CoreEnv = AppEnv;

type CoreContext = Context<CoreEnv>;

export function isJsonPath(path: string): boolean {
  return path.startsWith("/api/") || path === "/auth/refresh";
}

// The server pages: /auth, /auth/* and /authorize.
export function isPagePath(path: string): boolean {
  return path === "/auth" || path.startsWith("/auth/") || path === "/authorize";
}

// Error details for logs. Query parameters are omitted because they may contain hashes and emails.
export function describeError(error: unknown): Record<string, unknown> {
  if (!(error instanceof Error)) return { error: "unknown" };
  if (error instanceof DrizzleQueryError) {
    return { name: error.name, query: error.query, cause: error.cause instanceof Error ? error.cause.message : undefined };
  }
  const code = (error as { code?: unknown }).code;
  return { name: error.name, message: error.message, code: typeof code === "string" ? code : undefined };
}

export function apiError<E extends Env, S extends ContentfulStatusCode>(
  c: Context<E>,
  status: S,
  code: string,
  message: string,
) {
  const body: ApiError = { error: { code, message } };
  return c.json(body, status);
}

export type CurrentUser = { user: UserRow; sessionId: string };

export type MiddlewareDeps = {
  names: BrandNames;
  ErrorPage: (props: { message: string }) => PageMarkup;
};

export function createMiddleware({ names, ErrorPage }: MiddlewareDeps) {
  function errorResponse(c: CoreContext, status: ContentfulStatusCode, code: string, message: string) {
    if (isJsonPath(c.req.path)) return apiError(c, status, code, message);
    return c.html(ErrorPage({ message }), status);
  }

  // 1. Validates the configuration on every request.
  const loadConfigMiddleware: MiddlewareHandler<CoreEnv> = async (c, next) => {
    const result = loadConfig(c.env);
    if (!result.ok) {
      console.error("invalid configuration", { invalid: result.invalid });
      return errorResponse(c, 500, "internal_error", "サーバーの設定に誤りがあります");
    }
    c.set("config", result.config);
    c.set("db", createDb(c.env.DB));
    await next();
  };

  const securityHeaders: MiddlewareHandler<CoreEnv> = async (c, next) => {
    await next();
    const path = c.req.path;
    // A route that sets its own Cache-Control keeps it.
    if (
      (isPagePath(path) || path === "/api/v1" || path.startsWith("/api/v1/")) &&
      !c.res.headers.has("Cache-Control")
    ) {
      c.header("Cache-Control", "no-store");
    }
    if (isPagePath(path)) {
      c.header("Content-Security-Policy", "frame-ancestors 'none'");
      c.header("X-Content-Type-Options", "nosniff");
    }
  };

  // 2. In oidc mode, keeps /auth and /auth/* on APP_ORIGIN so that redirect_uri and cookies use one host.
  const unifyHost: MiddlewareHandler<CoreEnv> = async (c, next) => {
    const { oidc } = c.get("config");
    if (!oidc || !isPagePath(c.req.path)) return next();
    const url = new URL(c.req.url);
    if (url.origin === oidc.appOrigin) return next();
    if (c.req.method === "GET" || c.req.method === "HEAD") {
      return c.redirect(`${oidc.appOrigin}${url.pathname}${url.search}`, 302);
    }
    return c.notFound();
  };

  // 3. CSRF protection for cookie-authenticated routes.
  const sameOrigin: MiddlewareHandler<CoreEnv> = async (c, next) => {
    const method = c.req.method;
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") return next();
    const origin = c.req.header("Origin");
    const allowed =
      origin !== undefined
        ? origin === new URL(c.req.url).origin
        : c.req.header("Sec-Fetch-Site") === "same-origin";
    if (!allowed) return errorResponse(c, 403, "forbidden", "このリクエストは許可されていません");
    return next();
  };

  // 4. Routes that exist only in one auth mode return 404 in the other.
  function requireMode(mode: AuthMode): MiddlewareHandler<CoreEnv> {
    return async (c, next) => {
      if (c.get("config").authMode !== mode) return c.notFound();
      return next();
    };
  }

  // Resolves the signed-in user from the access token. Usable outside middleware (e.g. pages).
  async function getCurrentUser(c: CoreContext): Promise<CurrentUser | null> {
    const token = getAccessCookie(names, c);
    if (!token) return null;
    const now = clock.now();
    const claims = await verifyAccessToken(names, token, c.get("config").jwtSecret, now);
    if (!claims) return null;
    const db = c.get("db");
    const session = await db.select().from(sessions).where(eq(sessions.id, claims.sid)).get();
    if (!session || session.userId !== claims.sub || session.revokedAt !== null || session.familyExpiresAt <= now) {
      return null;
    }
    const user = await db.select().from(users).where(eq(users.id, claims.sub)).get();
    if (!user) return null;
    return { user, sessionId: session.id };
  }

  // 5.
  const requireUser: MiddlewareHandler<CoreEnv> = async (c, next) => {
    const current = await getCurrentUser(c);
    if (!current) return apiError(c, 401, "unauthorized", "ログインが必要です");
    c.set("user", current.user);
    c.set("sessionId", current.sessionId);
    return next();
  };

  // 6.
  const requireAdmin: MiddlewareHandler<CoreEnv> = async (c, next) => {
    if (c.get("user").role !== "admin") return apiError(c, 403, "forbidden", "管理者の権限が必要です");
    return next();
  };

  return {
    getCurrentUser,
    middleware: { securityHeaders, loadConfigMiddleware, unifyHost, sameOrigin, requireMode, requireUser, requireAdmin },
  };
}

export type CoreMiddleware = ReturnType<typeof createMiddleware>["middleware"];
