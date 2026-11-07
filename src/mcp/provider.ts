import type { OAuthProviderOptions } from "@cloudflare/workers-oauth-provider";
import type { CoreBindings } from "../config.js";
import { MCP_SCOPE } from "./handler.js";

export const MCP_ACCESS_TOKEN_TTL_SECONDS = 12 * 60 * 60;
export const MCP_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

export type FetchHandler<AppBindings> = {
  fetch(request: Request, env: AppBindings, ctx: ExecutionContext): Response | Promise<Response>;
};

export function buildOAuthProviderOptions<AppBindings extends CoreBindings>(
  origin: string,
  app: FetchHandler<AppBindings>,
  mcpHandler: FetchHandler<AppBindings>,
): OAuthProviderOptions<AppBindings> {
  return {
    apiRoute: "/mcp",
    apiHandler: mcpHandler,
    defaultHandler: { fetch: (request, env, ctx) => app.fetch(request, env, ctx) },
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/oauth/token",
    clientRegistrationEndpoint: "/oauth/register",
    scopesSupported: [MCP_SCOPE],
    requiredScopes: [MCP_SCOPE],
    resourceMetadata: { resource: `${origin}/mcp`, authorization_servers: [origin] },
    clientIdMetadataDocumentEnabled: true,
    // Longer than the 1 hour default to keep KV writes for refreshes low (the free plan allows
    // 1,000 writes a day). Users are read from the DB on every MCP request, so role changes and
    // deletions take effect immediately. On refresh, the library caps it at the grant's remaining lifetime.
    accessTokenTTL: MCP_ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTTL: MCP_REFRESH_TOKEN_TTL_SECONDS,
  };
}
