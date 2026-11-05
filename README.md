# @i2bskn/workers-app-core

Sign-in, user management and an MCP OAuth authorization server for [Hono](https://hono.dev) apps on Cloudflare
Workers with D1 and KV.

It provides:

- Web sign-in with email and password, or with an OpenID Connect provider (`AUTH_MODE=oidc`), with rotating refresh
  tokens stored in D1.
- The initial setup page that creates the first admin, and a JSON API to manage users (`/api/v1/me`,
  `/api/v1/users`).
- An OAuth 2.1 authorization server for MCP clients (`@cloudflare/workers-oauth-provider`), with dynamic client
  registration and Client ID Metadata Documents, a consent page, and a stateless MCP endpoint at `/mcp`
  (`@modelcontextprotocol/sdk`).
- The `users` and `sessions` tables (drizzle-orm), a browser-safe API client helper, and test helpers.

The server pages and API messages are in Japanese.

## Install

```sh
pnpm add @i2bskn/workers-app-core hono drizzle-orm @cloudflare/workers-oauth-provider @modelcontextprotocol/sdk @cfworker/json-schema openid-client zod
```

The listed libraries are peer dependencies, so that the app and the package share one copy of each.

## Entry points

| entry | contents |
| --- | --- |
| `@i2bskn/workers-app-core` | `createCore` and the server helpers |
| `@i2bskn/workers-app-core/schema` | the `users` and `sessions` tables and their row types |
| `@i2bskn/workers-app-core/client` | browser-safe: `createApiFetch`, `responseErrorMessage` and the API types |
| `@i2bskn/workers-app-core/testing` | `createTestHelpers` for tests with `@cloudflare/vitest-plugin` |

## Usage

```ts
// src/env.ts
import type { AppEnv as CoreAppEnv, CoreBindings } from "@i2bskn/workers-app-core";

export type Bindings = CoreBindings & { MY_QUEUE: Queue };
export type AppEnv = CoreAppEnv<Bindings>;
```

```ts
// src/core.ts
import { createCore } from "@i2bskn/workers-app-core";
import type { Bindings } from "./env";
import { registerTools } from "./mcp/tools";

export const core = createCore<Bindings>({
  brand: { id: "myapp", name: "My App", tagline: "What it does." },
  mcp: {
    serverInfo: { name: "myapp", version: "1.0.0" },
    register: (server, { db, user }) => registerTools(server, { db, user }),
  },
  consent: { description: "Once allowed, this app can read your projects." },
});
```

```ts
// src/app.ts
import { Hono } from "hono";
import { apiError, describeError, isJsonPath } from "@i2bskn/workers-app-core";
import { core } from "./core";
import type { AppEnv } from "./env";

const { securityHeaders, loadConfigMiddleware, unifyHost, sameOrigin } = core.middleware;

const app = new Hono<AppEnv>();
app.use("*", securityHeaders);
app.use("*", loadConfigMiddleware);
app.use("*", unifyHost);
// Cookie-authenticated routes only. /mcp and the OAuth endpoints must not use sameOrigin.
app.use("/auth/*", sameOrigin);
app.use("/api/v1/*", sameOrigin);
app.use("/authorize", sameOrigin);

app.route("/auth", core.routes.auth);
app.route("/authorize", core.routes.authorize);
const apiRoutes = app.route("/api/v1/me", core.routes.me).route("/api/v1/users", core.routes.users);
export type AppType = typeof apiRoutes;

app.notFound((c) => {
  if (isJsonPath(c.req.path)) return apiError(c, 404, "not_found", "見つかりません");
  return c.html(core.ErrorPage({ message: "ページが見つかりません" }), 404);
});
app.onError((error, c) => {
  console.error("unhandled error", describeError(error));
  if (isJsonPath(c.req.path)) return apiError(c, 500, "internal_error", "サーバーでエラーが発生しました");
  return c.html(core.ErrorPage({ message: "サーバーでエラーが発生しました" }), 500);
});

export default app;
```

```ts
// src/index.ts
import app from "./app";
import { core } from "./core";

export default { fetch: core.fetch(app) };
```

`core.fetch(app)` serves OAuth and `/mcp` through OAuthProvider on origins that can host them (https, loopback http
for local development, and only `APP_ORIGIN` in oidc mode), and passes everything else to the app. On other origins
the OAuth paths return 404.

The app's own routes use `core.middleware.requireUser`, `requireAdmin` and `requireMode`, and read `c.var.config`,
`c.var.db` and `c.var.user`.

## `createCore` options

```ts
createCore<AppBindings, AppVariables, AppProps, Extra, DeleteData>({ brand, hooks, mcp, consent });
```

- `AppBindings extends CoreBindings`: the app's bindings. `AppVariables` (default `{}`): extra Hono variables, merged
  with `config`, `db`, `user` and `sessionId`. `AppProps`: extra flat grant props (see MCP). `Extra`: the result of
  `mcp.checkRequest`. `DeleteData`: the result of `hooks.userDeleteStatements(...).read`.
- `brand.id`: `/^[a-z][a-z0-9-]{0,30}$/`, checked by `createCore` (it throws otherwise). `brand.name` is shown on the
  server pages, with `brand.tagline` below it. `brand.serverPagesCss` is the stylesheet of the server pages (default
  `/server-pages.css`, served by the app's static assets). `brand.layout({ title, children })` replaces the default
  layout.
- `hooks`: see below.
- `mcp.serverInfo`, `mcp.capabilities`, `mcp.parseProps`, `mcp.checkRequest`, `mcp.register`: see MCP.
- `consent.description`: the text of the default consent page, saying what an MCP client can do once allowed.
  `consent.render({ details, handle, email, description })` replaces the whole page; it must post `handle` and
  `decision` (`approve` or `deny`) to `/authorize`. One of the two is required.

Members of the returned core are bound to the brand: `routes.auth`, `routes.authorize`, `routes.me`, `routes.users`,
`middleware.*`, `getCurrentUser`, `signAccessToken`, `verifyAccessToken`, `setCookiesForSession`, `issueSession`,
`revokeAllGrants`, `buildOAuthProviderOptions(origin, app)`, `mcpHandler`, `ErrorPage` and `fetch(app)`.

## Hooks

Every hook is optional; without hooks only the package's own statements run.

- `userCreatedStatements(d1, userId, now): D1PreparedStatement[]`: appended after the INSERT of a user in the same
  `d1.batch`, at the initial setup, the first OIDC sign-in (just-in-time creation) and `POST /api/v1/users`. The setup
  INSERT is `INSERT ... WHERE NOT EXISTS (SELECT 1 FROM users)` and may insert nothing when two setups race, so each
  statement must guard itself with `EXISTS (SELECT 1 FROM users WHERE id = ?)`. Success is still decided by the
  INSERT. `d1` is `db.$client`. A UNIQUE violation in your statements fails the request with 500; only a violation
  of the `users` table itself is answered as a duplicate (`email_taken`, or a retry on the OIDC path).
- `beforeSessionIssued({ env, db, userId, now })`: called right before a web session is issued or rotated on sign-in:
  password login (after the password check), the OIDC callback (after the user is resolved), `POST /auth/refresh` and
  `GET /auth/login` with a valid refresh cookie (after the rotation, before the cookies). Not called on the setup, or
  when a concurrent rotation already won. An exception fails the request with 500 and sets no cookies.
  On the two refresh paths the rotation is already stored when the hook runs, so a failing hook leaves the browser
  with the previous refresh cookie: a retry within the reuse grace (10 seconds) is answered 401 without ending the
  session, and a retry after it is treated as token reuse and ends the session family. Keep the hook idempotent and
  make it fail only on real errors.
- `userDeleteStatements({ db, d1, userId, guard })`: returns `{ statements, read? }`, called after the checks for an
  unknown user and the last admin. The statements run first in the batch that deletes the sessions and the user.
  `guard` is the SQL that refuses the delete if the user is gone or is the last admin when the batch runs: every
  statement must include it. The guard binds the user ID as `?1`, so bind the user ID as `?1` and use `?2` and on for
  your own values. Success is decided by the final `DELETE FROM users ... RETURNING id`. `read(results)` receives the
  results of your statements only, in order, and its value is passed to `afterUserDeleted` as `data`.
- `afterUserDeleted({ env, userId, data })`: after the delete batch succeeded, before the user's MCP grants are
  revoked. Exceptions are logged and ignored; the grants are still revoked.
- `credentialsRevokedStatements({ db, userId, now, reason })`: drizzle query builders added to the batch that revokes
  credentials, after the revocation of the sessions. `reason` is `admin_reset` (an admin sets a password),
  `self_change` (the user changes their password; the statements run before the new session is inserted) or
  `revoke_sessions`. The MCP grants in KV are revoked before the batch.

## MCP

- Grant props are flat: `{ userId, authMode, authorizedAt, ...AppProps }`. App props must not use the base names;
  the base fields are always written last. `mcp.parseProps(raw)` validates the app fields and returns them, or `null`
  to reject the token with 401. The package validates the base fields.
- Per request, after the token is validated: `GET` and `DELETE` get 405, a token without the `mcp` scope gets 403,
  an invalid configuration 500. The token is rejected with 401 (`WWW-Authenticate` with `resource_metadata`) when the
  props are invalid, the auth mode changed, the user no longer exists, or `authorizedAt <= users.mcp_revoked_at`.
  Then `mcp.checkRequest(ctx)` may return a `Response` (sent as is) or `{ ok: true, extra }`, and
  `mcp.register(server, { ...ctx, extra })` registers the tools on a new stateless server. `ctx` has `request`, `env`,
  `ctx`, `auth`, `rawProps`, `props`, `config`, `db`, `user` and `invalidToken()`.
- OAuth endpoints: `/authorize`, `/oauth/token`, `/oauth/register`, metadata under `/.well-known/`, scope `mcp`.

### Custom authorization flows

The default `routes.authorize` asks for consent every time and revokes the earlier grants of the same client. A
custom flow can be built from `authorizationStartedAt`, `core.getCurrentUser`, `mapAuthorizeError`, `applyHeaders`,
`redirectWith`, `isPrefetch` and `completeMcpAuthorization`.

**Capture `authorizedAt` with `authorizationStartedAt()` as the first statement of the request that completes the
authorization, before the session check.** A revocation that is recorded in `users.mcp_revoked_at` while the request
runs then rejects the new grant too. `completeMcpAuthorization(oauth, { request, userId, authMode, authorizedAt,
props, metadata, revokeExistingGrants })` requires `authorizedAt` and `revokeExistingGrants`.

## Database

`@i2bskn/workers-app-core/schema` exports `users` and `sessions`. Re-export them from the app's drizzle schema so that
drizzle-kit includes them in the app's migrations:

```ts
export { users, sessions, type UserRow, type SessionRow } from "@i2bskn/workers-app-core/schema";
```

Apps own their migrations; the package ships none. `createDb(d1)` is `drizzle(d1)` without a schema (`db.query.*` is
not available), and `db.$client` is the D1 binding.

## Configuration

Variables and secrets:

| name | |
| --- | --- |
| `JWT_SECRET` | required, at least 32 characters |
| `AUTH_MODE` | `password` (default) or `oidc` |
| `APP_ORIGIN` | oidc: the https origin of the app |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | oidc |
| `ALLOWED_EMAILS` | oidc: comma separated emails or domains |
| `OIDC_REQUIRE_EMAIL_VERIFIED` | oidc: `false` accepts ID tokens without `email_verified` |

An invalid configuration answers every request with 500 without details, and logs the names of the invalid items.

`wrangler.jsonc` must have:

```jsonc
{
  // Required for Client ID Metadata Documents: fetches of client metadata must not reach internal addresses.
  "compatibility_flags": ["global_fetch_strictly_public"],
  "assets": {
    // The paths the package handles. Add the app's own paths.
    "run_worker_first": ["/api/*", "/auth", "/auth/*", "/authorize", "/mcp", "/mcp/*", "/oauth/*", "/.well-known/*"]
  },
  "d1_databases": [{ "binding": "DB", "database_name": "myapp", "migrations_dir": "drizzle/migrations" }],
  "kv_namespaces": [{ "binding": "OAUTH_KV" }]
}
```

## Security behaviors

- Cookies: `__Host-<id>_at` (access token, 15 minutes), `__Host-<id>_rt` (refresh token) and `__Host-<id>_oidc`
  (OIDC state, 10 minutes), all `HttpOnly; Secure; SameSite=Lax; Path=/`. Access tokens are HS256 JWTs with `iss`
  `<id>` and `aud` `<id>-web`; the OIDC state has `aud` `<id>-oidc`.
- Web sessions last 30 days in password mode and 24 hours in oidc mode, from the sign-in; refreshing rotates the
  refresh token without extending that. Reusing a rotated refresh token more than 10 seconds later revokes the whole
  session family. Switching `AUTH_MODE` revokes the sessions of the other mode on their next refresh.
- MCP access tokens last 12 hours, refresh tokens 30 days (24 hours in oidc mode).
- `ALLOWED_EMAILS`: an entry that is exactly `*` allows everyone; an empty list allows no one. Other entries match
  the whole email when they contain `@`, otherwise the domain exactly (subdomains do not match). Existing oidc
  sessions of users removed from the list are revoked on their next refresh.
- `users.mcp_revoked_at` is set when a password changes or an admin revokes a user's sessions. MCP tokens authorized
  at or before it are rejected, including grants that the revocation in KV missed. Deleting a user also revokes their
  grants; tokens of deleted users are rejected.
- POST requests to `/auth/*`, `/api/v1/*` and `/authorize` must be same-origin (`Origin`, or
  `Sec-Fetch-Site: same-origin` without it). Server pages are sent with `Cache-Control: no-store`,
  `Content-Security-Policy: frame-ancestors 'none'` and `X-Content-Type-Options: nosniff`.
- Passwords are hashed with PBKDF2-SHA256 (100,000 iterations) and must be 12 to 256 characters.

## Testing helpers

```ts
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { createTestHelpers } from "@i2bskn/workers-app-core/testing";
import worker from "../src/index";

export const { send, login, createUser, resetDb, sessionCookies } = createTestHelpers({
  worker,
  env,
  createExecutionContext,
  waitOnExecutionContext,
  brandId: "myapp",
  origin: "https://myapp.test",
});
```

`resetDb(appTables)` deletes the given tables (children first), then `sessions` and `users`. Also: `setCookies`,
`dbChangingBefore`, `d1With`, `d1RecordingLargeBinds`, `countTable`, and the constants `PASSWORD`, `TEST_JWT_SECRET`
and `D1_MAX_BOUND_VALUES`.

## License

Apache-2.0
