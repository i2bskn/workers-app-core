---
title: MCP
description: Grant props, per-request checks, OAuth endpoints and custom authorization flows.
---

## Grants and requests

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

## Custom authorization flows

The default `routes.authorize` asks for consent every time and revokes the earlier grants of the same client. A
custom flow can be built from `authorizationStartedAt`, `core.getCurrentUser`, `mapAuthorizeError`, `applyHeaders`,
`redirectWith`, `isPrefetch` and `completeMcpAuthorization`.

:::caution
Capture `authorizedAt` with `authorizationStartedAt()` as the first statement of the request that completes the
authorization, before the session check.
:::

A revocation that is recorded in `users.mcp_revoked_at` while the request runs then rejects the new grant too.
`completeMcpAuthorization(oauth, { request, userId, authMode, authorizedAt, props, metadata, revokeExistingGrants })`
requires `authorizedAt` and `revokeExistingGrants`.
