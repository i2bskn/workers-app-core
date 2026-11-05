import { Hono, type Context } from "hono";
import {
  AuthorizationError,
  CimdFetchError,
  type AuthRequest,
  type ConsentDescription,
  type OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";
import type { BrandLayout, PageMarkup } from "../brand.js";
import { clock } from "../clock.js";
import type { AuthMode } from "../config.js";
import type { CoreEnv, CurrentUser } from "../auth/middleware.js";
import { MCP_SCOPE, mergeMcpProps, type McpAppProps } from "../mcp/handler.js";
import { ErrorPage } from "../views/error.js";
import { isPrefetch } from "./auth.js";

type AnyContext = Context<any>;

// The time of an authorization. Take it first, before the session check: a revocation recorded in
// users.mcp_revoked_at while the request runs then rejects the new grant too.
export function authorizationStartedAt(): number {
  return clock.now();
}

// Copies headers from the consent helpers (cookies, no-store, no framing) to the response.
export function applyHeaders(c: AnyContext, headers: Headers): void {
  headers.forEach((value, name) => {
    if (name.toLowerCase() !== "set-cookie") c.header(name, value);
  });
  for (const cookie of headers.getSetCookie()) c.header("Set-Cookie", cookie, { append: true });
}

export function redirectWith(headers: Headers, location: string): Response {
  const result = new Headers(headers);
  result.set("Location", location);
  return new Response(null, { status: 302, headers: result });
}

// What to answer for an error of parseAuthRequest ("parse") or describeConsent ("describe"): a redirect back to
// the client, or a message for a local 400 page. null for other errors, which the caller rethrows. Logs a warning.
export type AuthorizeErrorResult = { redirectTo: string } | { status: 400; message: string };

export function mapAuthorizeError(error: unknown, stage: "parse" | "describe"): AuthorizeErrorResult | null {
  if (stage === "parse" && error instanceof AuthorizationError) {
    if (error.redirectTo) return { redirectTo: error.redirectTo };
    console.warn("oauth authorization request rejected", { code: error.code, description: error.description });
    return { status: 400, message: "接続の要求が正しくありません" };
  }
  if (error instanceof CimdFetchError) {
    console.warn("oauth client metadata unavailable", { reason: error.reason, detail: error.detail });
    return { status: 400, message: "アプリの情報を確認できませんでした" };
  }
  return null;
}

export type CompleteMcpAuthorizationOptions<AppProps extends object & McpAppProps> = {
  // ApprovedConsent.request.
  request: AuthRequest;
  userId: string;
  authMode: AuthMode;
  // From authorizationStartedAt(), taken before the session check.
  authorizedAt: number;
  props?: AppProps;
  metadata?: unknown;
  // true revokes the earlier grants of the same client, so that reconnecting an app leaves one grant.
  revokeExistingGrants: boolean;
};

// Completes an approved authorization with the package's grant props and the mcp scope.
export function completeMcpAuthorization<AppProps extends object & McpAppProps = {}>(
  oauth: OAuthHelpers,
  options: CompleteMcpAuthorizationOptions<AppProps>,
): Promise<{ redirectTo: string }> {
  const { request, userId, authMode, authorizedAt } = options;
  return oauth.completeAuthorization({
    request,
    userId,
    metadata: options.metadata ?? {},
    scope: [MCP_SCOPE],
    props: mergeMcpProps(options.props ?? {}, { userId, authMode, authorizedAt }),
    revokeExistingGrants: options.revokeExistingGrants,
  });
}

export type ConsentRenderProps = {
  details: ConsentDescription;
  handle: string;
  email: string;
  description: string | undefined;
};

export type AuthorizeRoutesDeps = {
  Layout: BrandLayout;
  getCurrentUser: (c: Context<CoreEnv>) => Promise<CurrentUser | null>;
  // Renders the consent page with consent.description.
  renderConsent: (props: Omit<ConsentRenderProps, "description">) => PageMarkup;
};

// The OAuth authorization endpoint for MCP clients. OAuthProvider validates the request, and this
// page signs the user in with the web session and asks for consent every time.
export function createAuthorizeRoutes({ Layout, getCurrentUser, renderConsent }: AuthorizeRoutesDeps) {
  const authorize = new Hono<CoreEnv>();

  // HEAD is routed here too; like prefetches, it must not write a consent transaction to KV.
  authorize.get("/", async (c) => {
    const oauth = c.env.OAUTH_PROVIDER;
    if (!oauth) return c.notFound();
    if (c.req.method === "HEAD" || isPrefetch(c)) return c.body(null, 204);

    // Validated before the sign-in, so that an invalid request does not lead to the login page.
    let authRequest;
    try {
      authRequest = await oauth.parseAuthRequest(c.req.raw);
    } catch (error) {
      const mapped = mapAuthorizeError(error, "parse");
      if (!mapped) throw error;
      if ("redirectTo" in mapped) return c.redirect(mapped.redirectTo, 302);
      return c.html(<ErrorPage Layout={Layout} message={mapped.message} />, 400);
    }

    const current = await getCurrentUser(c);
    if (!current) {
      const url = new URL(c.req.url);
      // GET /auth/login returns here after the sign-in (or after refreshing the session).
      return c.redirect(`/auth/login?next=${encodeURIComponent(`${url.pathname}${url.search}`)}`, 302);
    }

    let details;
    try {
      // Before beginConsent, so that a failed lookup leaves nothing in KV.
      details = await oauth.describeConsent(authRequest);
    } catch (error) {
      const mapped = mapAuthorizeError(error, "describe");
      if (!mapped || "redirectTo" in mapped) throw error;
      return c.html(<ErrorPage Layout={Layout} message={mapped.message} />, 400);
    }
    const consent = await oauth.beginConsent(authRequest);
    applyHeaders(c, consent.headers);
    return c.html(renderConsent({ details, handle: consent.handle, email: current.user.email }));
  });

  authorize.post("/", async (c) => {
    const oauth = c.env.OAUTH_PROVIDER;
    if (!oauth) return c.notFound();
    // Taken first: a revocation recorded in users.mcp_revoked_at while this request runs rejects the new grant too.
    const authorizedAt = authorizationStartedAt();

    const current = await getCurrentUser(c);
    if (!current) {
      return c.html(<ErrorPage Layout={Layout} message="ログインが切れました。接続をやり直してください" />, 401);
    }

    const body = await c.req.parseBody();
    const handle = typeof body.handle === "string" ? body.handle : "";
    let approved;
    try {
      if (body.decision !== "approve") {
        const denied = await oauth.denyConsent(c.req.raw, handle);
        return new Response(null, { status: 302, headers: denied.headers });
      }
      approved = await oauth.approveConsent(c.req.raw, handle, { scope: [MCP_SCOPE] });
    } catch (error) {
      if (error instanceof AuthorizationError) {
        console.warn("oauth consent rejected", { code: error.code, description: error.description });
        return c.html(
          <ErrorPage
            Layout={Layout}
            message="画面の有効期限が切れたか、別のブラウザで開かれました。接続をやり直してください"
          />,
          400,
        );
      }
      throw error;
    }

    // The earlier grants of the same client are revoked, so that reconnecting an app leaves one grant.
    const { redirectTo } = await completeMcpAuthorization(oauth, {
      request: approved.request,
      userId: current.user.id,
      authMode: c.get("config").authMode,
      authorizedAt,
      revokeExistingGrants: true,
    });
    return redirectWith(approved.headers, redirectTo);
  });

  return authorize;
}
