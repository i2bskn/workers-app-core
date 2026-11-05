import { insufficientScope, type OAuthResourceContext } from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { Implementation, ServerCapabilities } from "@modelcontextprotocol/sdk/types.js";
import { CfWorkerJsonSchemaValidator } from "@modelcontextprotocol/sdk/validation/cfworker";
import { findUserById } from "../auth/users.js";
import { loadConfig, type AuthMode, type Config, type CoreBindings } from "../config.js";
import { createDb, type Db } from "../db/client.js";
import type { UserRow } from "../db/schema.js";

export const MCP_SCOPE = "mcp";

// The fields of the grant props that the package owns. App props must not use these names.
export type McpBaseProps = { userId: string; authMode: AuthMode; authorizedAt: number };

export type McpAppProps = { userId?: never; authMode?: never; authorizedAt?: never };

// Stored in the grant at authorization and passed to the handler as ctx.props. authorizedAt is the time of the
// authorization (UNIX ms), compared with users.mcp_revoked_at. App props are flat, next to the base fields.
export type McpProps<AppProps extends object & McpAppProps = {}> = McpBaseProps & AppProps;

export function isMcpProps(value: unknown): value is McpBaseProps {
  if (typeof value !== "object" || value === null) return false;
  const { userId, authMode, authorizedAt } = value as Record<string, unknown>;
  return (
    typeof userId === "string" &&
    (authMode === "oidc" || authMode === "password") &&
    typeof authorizedAt === "number" &&
    Number.isFinite(authorizedAt)
  );
}

// Merges app props with the base fields. The base fields are written last and always win.
export function mergeMcpProps<AppProps extends object>(appProps: AppProps, base: McpBaseProps): McpProps<AppProps> {
  return { ...appProps, userId: base.userId, authMode: base.authMode, authorizedAt: base.authorizedAt };
}

// The same resource_metadata as the library's 401 for a missing token.
export function invalidTokenResponse(audience: string): Response {
  const metadataUrl = `${new URL(audience).origin}/.well-known/oauth-protected-resource/mcp`;
  return new Response(null, {
    status: 401,
    headers: {
      "Cache-Control": "no-store",
      "WWW-Authenticate": `Bearer error="invalid_token", resource_metadata="${metadataUrl}"`,
    },
  });
}

export type McpRequestContext<AppBindings extends CoreBindings = CoreBindings, AppProps extends object & McpAppProps = {}> = {
  request: Request;
  env: AppBindings;
  ctx: ExecutionContext;
  auth: OAuthResourceContext<unknown>["auth"];
  // ctx.props as stored in the grant.
  rawProps: unknown;
  props: McpProps<AppProps>;
  config: Config;
  db: Db;
  user: UserRow;
  // The 401 that makes the client authorize again.
  invalidToken(): Response;
};

export type McpCheckResult<Extra> = { ok: true; extra: Extra } | Response;

export type McpOptions<AppBindings extends CoreBindings = CoreBindings, AppProps extends object & McpAppProps = {}, Extra = undefined> = {
  serverInfo: Implementation;
  capabilities?: ServerCapabilities;
  // Validates the app fields of the grant props. null rejects the token with 401.
  parseProps?(raw: Record<string, unknown>): AppProps | null;
  // Runs after the package's checks. A Response is returned as is.
  checkRequest?(
    ctx: McpRequestContext<AppBindings, AppProps>,
  ): McpCheckResult<Extra> | Promise<McpCheckResult<Extra>>;
  // Registers the tools on the server of this request.
  register(server: McpServer, ctx: McpRequestContext<AppBindings, AppProps> & { extra: Extra }): void | Promise<void>;
};

// Called by OAuthProvider for /mcp after the access token has been validated.
export function createMcpHandler<AppBindings extends CoreBindings, AppProps extends object & McpAppProps, Extra>(
  options: McpOptions<AppBindings, AppProps, Extra>,
) {
  return {
    async fetch(request: Request, env: AppBindings, ctx: ExecutionContext): Promise<Response> {
      // Stateless: a GET would open an SSE stream that never carries anything, and there is no session to DELETE.
      if (request.method === "GET" || request.method === "DELETE") {
        return new Response(null, { status: 405, headers: { Allow: "POST" } });
      }

      const { auth, props: rawProps } = ctx as OAuthResourceContext<unknown>;
      if (!auth.scope.includes(MCP_SCOPE)) return insufficientScope(auth, [MCP_SCOPE]);

      const result = loadConfig(env);
      if (!result.ok) {
        console.error("invalid configuration", { invalid: result.invalid });
        return new Response(null, { status: 500 });
      }
      const config = result.config;
      const db = createDb(env.DB);
      const invalidToken = () => invalidTokenResponse(auth.audience);

      // The user is read on every request so that role changes and deletions apply immediately.
      // The grant is kept: a refreshed token also gets 401, and the client then authorizes again.
      if (!isMcpProps(rawProps) || rawProps.authMode !== config.authMode) return invalidToken();
      let appProps = {} as AppProps;
      if (options.parseProps) {
        const parsed = options.parseProps(rawProps as unknown as Record<string, unknown>);
        if (parsed === null) return invalidToken();
        appProps = parsed;
      }
      const props = mergeMcpProps(appProps, rawProps);
      const user = await findUserById(db, rawProps.userId);
      if (!user) return invalidToken();
      // Grants authorized at or before the last password change or session revocation, including those that the
      // revocation in KV missed because its listing lags behind.
      if (user.mcpRevokedAt !== null && rawProps.authorizedAt <= user.mcpRevokedAt) return invalidToken();

      const requestContext: McpRequestContext<AppBindings, AppProps> = {
        request,
        env,
        ctx,
        auth,
        rawProps,
        props,
        config,
        db,
        user,
        invalidToken,
      };
      let extra = undefined as Extra;
      if (options.checkRequest) {
        const checked = await options.checkRequest(requestContext);
        if (checked instanceof Response) return checked;
        extra = checked.extra;
      }

      // A new server and transport per request (stateless).
      const server = new McpServer(
        options.serverInfo,
        // The validator avoids compiling Ajv on every request.
        options.capabilities === undefined
          ? { jsonSchemaValidator: new CfWorkerJsonSchemaValidator() }
          : { capabilities: options.capabilities, jsonSchemaValidator: new CfWorkerJsonSchemaValidator() },
      );
      await options.register(server, { ...requestContext, extra });
      const transport = new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      await server.connect(transport);
      return transport.handleRequest(request);
    },
  };
}
