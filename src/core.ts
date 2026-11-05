import type { Context, Env, MiddlewareHandler } from "hono";
import type { HonoBase } from "hono/hono-base";
import { OAuthProvider, type OAuthHelpers, type OAuthProviderOptions } from "@cloudflare/workers-oauth-provider";
import { brandNames, type Brand, type PageMarkup } from "./brand.js";
import { loadConfig, type AppEnv, type AuthMode, type Config, type CoreBindings } from "./config.js";
import type { Db } from "./db/client.js";
import type { CoreHooks } from "./hooks.js";
import { setCookiesForSession } from "./auth/cookies.js";
import { createMiddleware, type CurrentUser } from "./auth/middleware.js";
import { issueSession, type NewSession } from "./auth/sessions.js";
import { signAccessToken, verifyAccessToken, type AccessTokenClaims } from "./auth/tokens.js";
import { revokeAllGrants } from "./mcp/grants.js";
import { createMcpHandler, type McpAppProps, type McpOptions } from "./mcp/handler.js";
import { buildOAuthProviderOptions, type FetchHandler } from "./mcp/provider.js";
import { createAuthRoutes } from "./routes/auth.js";
import { createAuthorizeRoutes, type ConsentRenderProps } from "./routes/authorize.js";
import { createMeRoutes } from "./routes/me.js";
import { createUsersRoutes } from "./routes/users.js";
import { ConsentPage } from "./views/consent.js";
import { ErrorPage } from "./views/error.js";
import { createDefaultLayout } from "./views/layout.js";

export type ConsentOptions = {
  // What the client can do once allowed, shown on the default consent page.
  description?: string;
  // Replaces the whole consent page. It must post `handle` and `decision` ("approve" or "deny") to /authorize.
  render?: (props: ConsentRenderProps) => PageMarkup;
};

type AnyHono = HonoBase<any, any, any, any>;

// The same routes, typed with the app's environment, so that hc<AppType>() keeps their types.
type Rebind<T extends AnyHono, E extends Env> =
  T extends HonoBase<any, infer S, infer BasePath, infer CurrentPath> ? HonoBase<E, S, BasePath, CurrentPath> : never;

export type CoreOptions<
  AppBindings extends CoreBindings,
  AppProps extends object & McpAppProps,
  Extra,
  DeleteData,
> = {
  brand: Brand;
  hooks?: CoreHooks<AppBindings, DeleteData>;
  mcp: McpOptions<AppBindings, AppProps, Extra>;
  consent: ConsentOptions;
};

export function createCore<
  AppBindings extends CoreBindings,
  AppVariables extends object = {},
  AppProps extends object & McpAppProps = {},
  Extra = undefined,
  DeleteData = undefined,
>(options: CoreOptions<AppBindings, AppProps, Extra, DeleteData>) {
  type E = AppEnv<AppBindings, AppVariables>;
  const { brand, consent } = options;
  const names = brandNames(brand.id);
  if (consent.description === undefined && consent.render === undefined) {
    throw new Error("createCore: consent.description or consent.render is required");
  }
  const hooks = (options.hooks ?? {}) as CoreHooks<CoreBindings, unknown>;
  const Layout = brand.layout ?? createDefaultLayout(brand);
  const errorPage = (props: { message: string }): PageMarkup => ErrorPage({ Layout, message: props.message });
  const { middleware, getCurrentUser } = createMiddleware({ names, ErrorPage: errorPage });

  const renderConsent = (props: Omit<ConsentRenderProps, "description">): PageMarkup => {
    const full = { ...props, description: consent.description };
    return consent.render ? consent.render(full) : ConsentPage({ ...full, Layout });
  };

  const authRoutes = createAuthRoutes({ names, Layout, middleware, hooks });
  const authorizeRoutes = createAuthorizeRoutes({ Layout, getCurrentUser, renderConsent });
  const meRoutes = createMeRoutes({ names, middleware, hooks });
  const usersRoutes = createUsersRoutes({ middleware, hooks });

  const mcpHandler = createMcpHandler(options.mcp);

  const buildOptions = (origin: string, app: FetchHandler<AppBindings>): OAuthProviderOptions<AppBindings> =>
    buildOAuthProviderOptions(origin, app, mcpHandler);

  // resourceMetadata.resource must be a fixed absolute URL, so there is one provider per app and origin.
  const providers = new WeakMap<FetchHandler<AppBindings>, Map<string, OAuthProvider<AppBindings>>>();
  function getOAuthProvider(origin: string, app: FetchHandler<AppBindings>): OAuthProvider<AppBindings> {
    let byOrigin = providers.get(app);
    if (!byOrigin) {
      byOrigin = new Map();
      providers.set(app, byOrigin);
    }
    let provider = byOrigin.get(origin);
    if (!provider) {
      provider = new OAuthProvider(buildOptions(origin, app));
      byOrigin.set(origin, provider);
    }
    return provider;
  }

  // The Worker's fetch handler: OAuthProvider on origins that can host OAuth, the app elsewhere.
  function fetch(app: FetchHandler<AppBindings>) {
    return async (request: Request, env: AppBindings, ctx: ExecutionContext): Promise<Response> => {
      const result = loadConfig(env);
      // The app answers with the same 500 as for any other path (loadConfigMiddleware).
      if (!result.ok) return app.fetch(request, env, ctx);

      const url = new URL(request.url);
      const origin = resolveOrigin(result.config, url);
      if (origin === null) {
        if (isOAuthPath(url.pathname)) return new Response(null, { status: 404 });
        // In oidc mode, unifyHost redirects pages to APP_ORIGIN.
        return app.fetch(request, env, ctx);
      }
      // A shallow copy per request: OAuthProvider sets env.OAUTH_PROVIDER only when it is missing,
      // so a shared env would keep the helpers of the first origin.
      return getOAuthProvider(origin, app).fetch(request, { ...env }, ctx);
    };
  }

  return {
    brand,
    getCurrentUser: getCurrentUser as <C extends E>(c: Context<C, any, any>) => Promise<CurrentUser | null>,
    signAccessToken: (claims: { sub: string; sid: string }, secret: string, now: number): Promise<string> =>
      signAccessToken(names, claims, secret, now),
    verifyAccessToken: (
      token: string,
      secret: string,
      now: number,
      verifyOptions: { allowExpired?: boolean } = {},
    ): Promise<AccessTokenClaims | null> => verifyAccessToken(names, token, secret, now, verifyOptions),
    setCookiesForSession: <C extends E>(
      c: Context<C, any, any>,
      session: NewSession,
      secret: string,
      now: number,
    ): Promise<void> => setCookiesForSession(names, c, session, secret, now),
    issueSession: (db: Db, userId: string, mode: AuthMode, now: number): Promise<NewSession> =>
      issueSession(db, userId, mode, now),
    revokeAllGrants: (oauth: OAuthHelpers, userId: string): Promise<void> => revokeAllGrants(oauth, userId),
    buildOAuthProviderOptions: buildOptions,
    // The handler OAuthProvider calls for /mcp, for tests that call it with a prepared context.
    mcpHandler,
    ErrorPage: errorPage,
    fetch,
    routes: {
      auth: authRoutes as unknown as Rebind<typeof authRoutes, E>,
      authorize: authorizeRoutes as unknown as Rebind<typeof authorizeRoutes, E>,
      me: meRoutes as unknown as Rebind<typeof meRoutes, E>,
      users: usersRoutes as unknown as Rebind<typeof usersRoutes, E>,
    },
    middleware: {
      securityHeaders: middleware.securityHeaders as unknown as MiddlewareHandler<E>,
      loadConfigMiddleware: middleware.loadConfigMiddleware as unknown as MiddlewareHandler<E>,
      unifyHost: middleware.unifyHost as unknown as MiddlewareHandler<E>,
      sameOrigin: middleware.sameOrigin as unknown as MiddlewareHandler<E>,
      requireMode: middleware.requireMode as unknown as (mode: AuthMode) => MiddlewareHandler<E>,
      requireUser: middleware.requireUser as unknown as MiddlewareHandler<E>,
      requireAdmin: middleware.requireAdmin as unknown as MiddlewareHandler<E>,
    },
  };
}

export type Core = ReturnType<typeof createCore>;

// Paths served by OAuthProvider or the authorization page. They are never forwarded to another host.
// Every top-level path here must be in assets.run_worker_first of wrangler.jsonc.
function isOAuthPath(path: string): boolean {
  return (
    path === "/mcp" ||
    path.startsWith("/mcp/") ||
    path.startsWith("/oauth/") ||
    path.startsWith("/.well-known/") ||
    path === "/authorize"
  );
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "[::1]" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

// The origin that hosts OAuth and MCP for this request, or null if the request cannot use them.
function resolveOrigin(config: Config, url: URL): string | null {
  if (config.oidc) return url.origin === config.oidc.appOrigin ? url.origin : null;
  // OAuth requires https, except on loopback hosts for local development.
  if (url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHostname(url.hostname))) {
    return url.origin;
  }
  return null;
}
