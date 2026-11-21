# @i2bskn/workers-app-core

Sign-in, user management and an MCP OAuth authorization server for [Hono](https://hono.dev) apps on Cloudflare
Workers with D1 and KV.

It provides:

- Web sign-in with email and password, or with an OpenID Connect provider (`AUTH_MODE=oidc`), with rotating refresh
  tokens stored in D1.
- The initial setup page that creates the first admin, invitation links for password mode, and a JSON API to manage
  users (`/api/v1/me`, `/api/v1/users`). In oidc mode, only users registered by an admin can sign in.
- An OAuth 2.1 authorization server for MCP clients (`@cloudflare/workers-oauth-provider`), with dynamic client
  registration and Client ID Metadata Documents, a consent page, and a stateless MCP endpoint at `/mcp`
  (`@modelcontextprotocol/sdk`).
- Drizzle tables for users, sessions, and password MFA, a browser-safe API client helper, and test helpers.

The server pages and API messages are in Japanese.

## Install

```sh
pnpm add @i2bskn/workers-app-core hono drizzle-orm @cloudflare/workers-oauth-provider @modelcontextprotocol/sdk @cfworker/json-schema openid-client zod
```

The app shares its peer dependencies with the core. The core installs its WebAuthn verifier (`@simplewebauthn/server`) and TOTP QR encoder (`uqr`) as runtime dependencies.

## Entry points

| entry | contents |
| --- | --- |
| `@i2bskn/workers-app-core` | `createCore` and the server helpers |
| `@i2bskn/workers-app-core/schema` | core authentication tables and row types |
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

`issueSession(db, userId, config, now)` takes the `Config` (`c.var.config`) and creates a session of
`config.authMode`, with the lifetime of `config.session`. `setCookiesForSession(c, session, secret, now)` sets the
Max-Age of the refresh cookie from `session.expiresAt`. Use `core.issueSession` only in trusted server code after
the caller has authenticated the user and completed any required MFA. For browser sign-in, use the core auth routes.

Breaking changes in 0.4.0:

- `ALLOWED_EMAILS` is removed and no longer read (a value left in the environment is ignored, not an error). In oidc
  mode, a first sign-in is allowed only for users that an admin registered beforehand (`POST /api/v1/users`), and for
  `INITIAL_ADMIN_EMAIL` while there are no users. Existing users can still sign in, including users created by a
  domain entry or `*` in `ALLOWED_EMAILS`, and users removed from `ALLOWED_EMAILS` to stop their sign-in (their rows
  remain). **Before upgrading**, compare the user list with `ALLOWED_EMAILS` and delete the users who must not sign
  in; deleting a user also ends their sessions and MCP grants. Then remove `ALLOWED_EMAILS`.
- Refreshing an oidc session no longer revokes it for users outside `ALLOWED_EMAILS`. Delete a user to stop them.
- `POST /api/v1/users` is available in oidc mode as well, without a password. `CreateUserRequest.password` is
  optional (and may be `null`), and `CreateUserInput.password` is `string | null`.
- `OidcConfig.allowedEmails` is removed and `OidcConfig.initialAdminEmail` (`string | null`) is added.
- A `user_invitations` table is added. Re-export the core tables, run `drizzle-kit generate` and apply the migration
  to D1 before deploying.
- `User` has a `status` (`"active"` or `"invited"`). `POST /api/v1/users` answers a `CreateUserResponse` (the `User`
  with an `invitation`).
- The exported `toApiUser(user, authMode)` takes the auth mode.
- `CredentialsRevokedReason` has a new member, `"admin_mfa_reset"` (`POST /api/v1/users/:id/reset-mfa`). An exhaustive
  `switch` on the `reason` of `credentialsRevokedStatements` needs a case for it.

Breaking changes in 0.3.0:

- Password sign-in reads the MFA tables, even under the default `optional` policy. Before deploying, re-export the
  core tables (`export * from "@i2bskn/workers-app-core/schema"`), run `drizzle-kit generate`, and apply the
  migration to D1.

Breaking changes in 0.2.0:

- `issueSession` takes a `Config` instead of an `AuthMode`; it can no longer create a session of another mode than
  the configuration.
- `Config` has a required `session: SessionConfig` (`{ maxAgeMs, idleTimeoutMs }`).
- `NewSession` has a required `expiresAt`, and `setCookiesForSession` computes the Max-Age of the refresh cookie from
  it instead of `familyExpiresAt`.

## Hooks

Every hook is optional; without hooks only the package's own statements run.

- `userCreatedStatements(d1, userId, now): D1PreparedStatement[]`: appended after the INSERT of a user in the same
  `d1.batch`, at the initial setup, the first OIDC sign-in of `INITIAL_ADMIN_EMAIL` (the creation of the first admin)
  and `POST /api/v1/users`. The INSERTs of the setup and of the first admin are
  `INSERT ... WHERE NOT EXISTS (SELECT 1 FROM users)` and may insert nothing when two sign-ins race, so each
  statement must guard itself with `EXISTS (SELECT 1 FROM users WHERE id = ?)`. Success is still decided by the
  INSERT. `d1` is `db.$client`. A UNIQUE violation in your statements fails the request with 500; only a violation
  of the `users` table itself is answered as a duplicate (`email_taken`, or a retry on the OIDC path).
- `beforeOidcUserLinkOrCreate({ operation, env, db, issuer, subject, email, claims })`: after the ID token checks,
  authorize the first association with an OIDC identity. `operation` is `"link"` for the first sign-in of a user
  registered beforehand (an invitation), and `"create"` only for the creation of the first admin by
  `INITIAL_ADMIN_EMAIL`. Return `true` to allow it, or `false` for a 403 before the user write or session
  issuance. An exception fails the request with 500. The hook receives the normalized email and the verified token
  claims, e.g. to require a Google `hd` claim. Already linked issuer/subject pairs skip this hook, including when the
  email changes, and so do emails that are not invited (they get a 403 without any write). Concurrent sign-ins
  can cause a retry: use this hook for checks, and commit one-time effects atomically with the user write.
- `beforeSessionIssued({ env, db, userId, now })`: called right before a web session is issued or rotated on sign-in:
  password login (after all required factors), the sign-in after accepting an invitation link (likewise), the OIDC
  callback (after the user is resolved), `POST /auth/refresh` and
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
  `self_change` (the user changes their password; the statements run before the new session is inserted),
  `revoke_sessions` or `admin_mfa_reset` (an admin resets the user's MFA; the statements run before the MFA factors
  are deleted, so the MFA rows still exist). The MCP grants in KV are revoked before the batch.

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

Re-export the core tables (`users`, `sessions`, `user_invitations` and the password MFA tables) from the app's
Drizzle schema. Generate and apply the app's schema migration before deploying a version that queries the new tables. When upgrading a password-mode app that re-exports only
`users` and `sessions`, use the export below, run `drizzle-kit generate`, apply the generated migration
to D1, then deploy the Worker. Password sign-in checks the MFA tables even under the default optional policy.

```ts
export * from "@i2bskn/workers-app-core/schema";
```

Apps own their migrations; the package ships none. `createDb(d1)` is `drizzle(d1)` without a schema (`db.query.*` is
not available), and `db.$client` is the D1 binding.

## Configuration

Variables and secrets:

| name | |
| --- | --- |
| `JWT_SECRET` | required, at least 32 characters |
| `AUTH_MODE` | `password` (default) or `oidc` |
| `APP_ORIGIN` | canonical HTTPS origin of the app. Required for OIDC and for WebAuthn. |
| `PASSWORD_MFA_POLICY` | password: `optional` (default), `admins`, or `all`. An enrolled account always completes MFA on password login. |
| `PASSWORD_MFA_KEY` | password: 32 random bytes in standard base64 (generate with `openssl rand -base64 32`). Store as a Worker Secret to enable TOTP. |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | oidc |
| `INITIAL_ADMIN_EMAIL` | oidc: while there are no users, the first sign-in with this email creates the first admin. Ignored once a user exists. |
| `OIDC_REQUIRE_EMAIL_VERIFIED` | oidc: `false` accepts ID tokens without `email_verified` (see below) |
| `SESSION_MAX_AGE_HOURS` | absolute lifetime of web sessions from the sign-in, in hours (default 720 in password mode, 24 in oidc mode) |
| `SESSION_IDLE_TIMEOUT_HOURS` | lifetime of web sessions from the last refresh, in hours (default: none) |

### Users

In password mode, the first admin is created on the initial setup page (`/auth/setup`), which is open only while
there are no users: complete it right after deploying. Admins then add users with `POST /api/v1/users`, either with
an initial password, or without one to get an invitation link (see below).

In oidc mode, sign-in is by invitation. While there are no users, the first sign-in with `INITIAL_ADMIN_EMAIL`
creates the first admin; without `INITIAL_ADMIN_EMAIL`, nobody can sign in to an empty deployment (logged as
`initial_admin_not_configured`). Admins register users with `POST /api/v1/users` (an email and a role, no password).
Only registered emails can sign in for the first time: the email of the ID token must match the registered user,
whose OIDC `iss` and `sub` are then linked to it. Later sign-ins identify the user by `iss` and `sub`, and the email
is not compared again. Other emails get a 403, and no user or session is created. Deleting a user who has not
signed in yet withdraws the invitation; deleting a user who has signed in stops them (their sessions and MCP grants
end too). An invalid `INITIAL_ADMIN_EMAIL` is a configuration error.

`OIDC_REQUIRE_EMAIL_VERIFIED=false` accepts ID tokens without `email_verified` (a claim that is present must still
be `true`). Use it only when the IdP guarantees verified emails by other means: if the IdP lets someone sign in with
an email they have not verified, they can be linked to an invited user or to `INITIAL_ADMIN_EMAIL` and take over
that account.

`SESSION_MAX_AGE_HOURS` and `SESSION_IDLE_TIMEOUT_HOURS` are whole numbers from 1 to 9600 (400 days), written as
strings (`"168"`, not `168`, in `vars`); any other value is a configuration error. An idle timeout longer than the
max age is accepted and has no effect.

### Password MFA

Configure `APP_ORIGIN` to offer WebAuthn passkeys and security keys. Set `PASSWORD_MFA_KEY` to also offer
authenticator apps (TOTP). Keep this encryption key stable and backed up independently of `JWT_SECRET`.
Changing it makes existing TOTP secrets unreadable; users can recover with an unused recovery code.
A required policy needs at least one configured enrollment method. In password mode, an unsupported
`APP_ORIGIN` disables WebAuthn. When WebAuthn is the only method, open initial setup at the configured origin.
Each pending sign-in or registration allows five verification attempts. Unsuccessful checks of an already
registered TOTP also introduce an account-wide delay for that method. After attempts 5, 10,
15 and 20, the minimum interval increases to 5 minutes, 30 minutes, 4 hours and 24 hours respectively.
Successful authentication, a password change, or an administrator password reset clears this delay.
A user can still start a fresh flow with a passkey or recovery code while TOTP is waiting.

Users can enroll from the password login or visit `/auth/mfa/manage`. Adding or replacing an enrolled factor
requires the password and an existing factor or recovery code. A user who has lost both their factors and their
recovery codes needs an admin to reset their MFA (see below). The same checks apply when disabling voluntary
MFA. Store the single-use recovery codes away from the authenticator. On the recovery form, users can
choose to replace a lost device. Using the last code starts replacement automatically. The code remains
valid until registration completes, so users can restart an interrupted registration. To replace a registered
passkey, use another authenticator or TOTP. The existing credentials work until the replacement is confirmed. Adding or replacing
a factor using a recovery code issues a new set of codes. A password reset preserves the account's factors.
`admins` requires enrollment for administrators, and `all` for everyone, including the first admin at setup.
Each fresh password sign-in applies the current policy before issuing a session. Enabling MFA does not revoke
existing web sessions or MCP grants, and refreshing their tokens does not prompt for a second factor.
OIDC applications use their identity provider's MFA policy.

An admin resets another user's MFA with `POST /api/v1/users/:id/reset-mfa` (password mode only; 404 in oidc mode).
It deletes all of the user's factors (passkeys, TOTP and recovery codes) and any MFA flow in progress, revokes their
web sessions and MCP grants, and keeps their password. It answers 204, 409 `mfa_not_enrolled` for a user without
MFA, and 400 `cannot_reset_own_mfa` for the requesting admin: admins change their own factors at
`/auth/mfa/manage`, and another admin resets a locked-out admin. After the reset, a user whom the policy requires to
use MFA enrolls a new factor at the next password sign-in. **At that point the password alone is enough to enroll,
so anyone who knows the password could enroll first: confirm the user's identity before resetting, and ask them to
sign in and enroll right away.** If the password may have leaked with the device (e.g. a stolen device), reset the
password as well with `POST /api/v1/users/:id/password`. An admin who resets both a user's password and MFA can
enroll new factors and sign in as that user, so MFA does not protect users against admins.

When the only admin has lost their factors and recovery codes, the deployer deletes the MFA rows in D1 directly,
child tables first so that the result does not depend on foreign key behavior:

```sh
wrangler d1 execute <DATABASE> --remote --command "
DELETE FROM mfa_pending WHERE user_id = (SELECT id FROM users WHERE email = 'admin@example.com');
DELETE FROM mfa_recovery_codes WHERE user_id = (SELECT id FROM users WHERE email = 'admin@example.com');
DELETE FROM mfa_credentials WHERE user_id = (SELECT id FROM users WHERE email = 'admin@example.com');
DELETE FROM mfa_accounts WHERE user_id = (SELECT id FROM users WHERE email = 'admin@example.com');
"
```

`users.email` stores the normalized (lowercase) address. This does not revoke sessions or MCP grants; if needed,
the admin can revoke their own sessions with `POST /api/v1/users/:id/revoke-sessions` after signing in.

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
- Web sessions last `SESSION_MAX_AGE_HOURS` from the sign-in (by default 30 days in password mode and 24 hours in
  oidc mode); refreshing rotates the refresh token without extending that. With `SESSION_IDLE_TIMEOUT_HOURS`, a
  session also expires when it has not been refreshed for that long, and each refresh extends it up to the earlier of
  the max age and the refresh time plus the idle timeout. The refresh cookie's Max-Age follows that expiry. Expiring
  by the idle timeout does not revoke the session family. Reusing a rotated refresh token more than 10 seconds later
  revokes the whole session family. Switching `AUTH_MODE` revokes the sessions of the other mode on their next refresh.
- The max age of a session is fixed at the sign-in: changing `SESSION_MAX_AGE_HOURS` applies from the next sign-in.
  The idle timeout is computed with the current setting: shortening it applies to existing sessions at once, and
  lengthening or removing it makes sessions that had passed it valid again if they are within their max age (only a
  copy of the token can use them, since browsers drop the cookie at its Max-Age).
- The idle timeout counts from the last refresh. Clients refresh when the access token (15 minutes) has expired and a
  request gets 401, so the inactivity actually allowed is between about the idle timeout minus 15 minutes and the
  idle timeout.
- MCP access tokens last 12 hours, refresh tokens 30 days in both modes.
- Invitation links (password mode): `POST /api/v1/users` without a password creates a user without a password and
  returns `invitation: { url, expires_at }`; `POST /api/v1/users/:id/invitation` issues a new link for such a user,
  replacing the previous one (409 `already_active` once a password is set). The link is
  `<origin>/auth/invite?token=...`, where the origin is `APP_ORIGIN` when it is a valid HTTPS origin, otherwise the
  origin of the API request. `GET /auth/invite` shows the password form and `POST /auth/invite` sets the password and
  signs the user in (through MFA enrollment when the policy requires it). Only the SHA-256 hash of the token is
  stored, the URL is returned only when it is issued, and the token is never logged. A link is valid for 7 days and
  only once: setting the password consumes it, and so does an admin setting the password. Deleting the user deletes
  it. The token is in the query string, so it may remain in the browser history and in platform request logs (e.g.
  Workers observability); the pages are sent with `Referrer-Policy: same-origin` (the URL is not sent to other sites;
  `no-referrer` would make browsers send `Origin: null` with the form, which `sameOrigin` rejects) and
  `Cache-Control: no-store`.
- `users.mcp_revoked_at` is set when a password changes, an admin revokes a user's sessions or an admin resets a
  user's MFA. MCP tokens authorized at or before it are rejected, including grants that the revocation in KV missed.
  Deleting a user also revokes their grants; tokens of deleted users are rejected.
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

`resetDb(appTables)` deletes the given tables (children first), then `sessions`, `user_invitations` and `users`. Also: `setCookies`,
`dbChangingBefore`, `d1With`, `d1RecordingLargeBinds`, `countTable`, and the constants `PASSWORD`, `TEST_JWT_SECRET`
and `D1_MAX_BOUND_VALUES`.

## License

MIT
