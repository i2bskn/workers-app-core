---
title: createCore options
description: Type parameters, options and the members of the returned core.
---

```ts
createCore<AppBindings, AppVariables, AppProps, Extra, DeleteData>({
  brand,
  hooks,
  mcp,
  consent,
});
```

## Options

- `AppBindings extends CoreBindings`: the app's bindings. `AppVariables` (default `{}`): extra Hono variables, merged
  with `config`, `db`, `user` and `sessionId`. `AppProps`: extra flat grant props (see
  [MCP](/workers-app-core/guides/mcp/)). `Extra`: the result of `mcp.checkRequest`. `DeleteData`: the result of
  `hooks.userDeleteStatements(...).read`.
- `brand.id`: `/^[a-z][a-z0-9-]{0,30}$/`, checked by `createCore` (it throws otherwise). `brand.name` is shown on the
  server pages, with `brand.tagline` below it. `brand.serverPagesCss` is the stylesheet of the server pages (default
  `/server-pages.css`, served by the app's static assets). `brand.layout({ title, children })` replaces the default
  layout.
- `hooks`: see [Hooks](/workers-app-core/reference/hooks/).
- `mcp.serverInfo`, `mcp.capabilities`, `mcp.parseProps`, `mcp.checkRequest`, `mcp.register`: see
  [MCP](/workers-app-core/guides/mcp/).
- `consent.description`: the text of the default consent page, saying what an MCP client can do once allowed.
  `consent.render({ details, handle, email, description })` replaces the whole page; it must post `handle` and
  `decision` (`approve` or `deny`) to `/authorize`. One of the two is required.

## The returned core

Members of the returned core are bound to the brand: `routes.auth`, `routes.authorize`, `routes.me`, `routes.users`,
`middleware.*`, `getCurrentUser`, `signAccessToken`, `verifyAccessToken`, `setCookiesForSession`, `issueSession`,
`revokeAllGrants`, `buildOAuthProviderOptions(origin, app)`, `mcpHandler`, `ErrorPage` and `fetch(app)`.

`issueSession(db, userId, config, now)` takes the `Config` (`c.var.config`) and creates a session of
`config.authMode`, with the lifetime of `config.session`. `setCookiesForSession(c, session, secret, now)` sets the
Max-Age of the refresh cookie from `session.expiresAt`. Use `core.issueSession` only in trusted server code after
the caller has authenticated the user and completed any required MFA. For browser sign-in, use the core auth routes.
