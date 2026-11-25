---
title: Usage
description: Create the core and mount its routes and middleware on a Hono app.
---

An app wires the core in with four files.

## 1. Declare the bindings

`src/env.ts` adds the app's own bindings to `CoreBindings` and builds the Hono environment type from them.

```ts
// src/env.ts
import type { AppEnv as CoreAppEnv, CoreBindings } from "@i2bskn/workers-app-core";

export type Bindings = CoreBindings & { MY_QUEUE: Queue };
export type AppEnv = CoreAppEnv<Bindings>;
```

## 2. Create the core

`src/core.ts` creates the core with the brand, the MCP tools and the text of the consent page. See
[`createCore` options](/workers-app-core/reference/create-core/) for every option.

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

## 3. Mount the middleware and routes

`src/app.ts` adds the core's middleware and routes to the Hono app, and answers unknown paths and errors with the
core's error page.

```ts
// src/app.ts
import { Hono } from "hono";
import { apiError, describeError, isJsonPath } from "@i2bskn/workers-app-core";
import { core } from "./core";
import type { AppEnv } from "./env";

const { securityHeaders, loadConfigMiddleware, unifyHost, sameOrigin } =
  core.middleware;

const app = new Hono<AppEnv>();
app.use("*", securityHeaders);
app.use("*", loadConfigMiddleware);
app.use("*", unifyHost);
// Cookie-authenticated routes only.
// /mcp and the OAuth endpoints must not use sameOrigin.
app.use("/auth/*", sameOrigin);
app.use("/api/v1/*", sameOrigin);
app.use("/authorize", sameOrigin);

app.route("/auth", core.routes.auth);
app.route("/authorize", core.routes.authorize);
const apiRoutes = app
  .route("/api/v1/me", core.routes.me)
  .route("/api/v1/users", core.routes.users);
export type AppType = typeof apiRoutes;

app.notFound((c) => {
  if (isJsonPath(c.req.path)) {
    return apiError(c, 404, "not_found", "見つかりません");
  }
  return c.html(
    core.ErrorPage({ message: "ページが見つかりません" }),
    404,
  );
});
app.onError((error, c) => {
  console.error("unhandled error", describeError(error));
  if (isJsonPath(c.req.path)) {
    return apiError(
      c,
      500,
      "internal_error",
      "サーバーでエラーが発生しました",
    );
  }
  return c.html(
    core.ErrorPage({ message: "サーバーでエラーが発生しました" }),
    500,
  );
});

export default app;
```

## 4. Serve the app

`src/index.ts` exports `core.fetch(app)` as the fetch handler of the Worker.

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

## Next

- [`createCore` options](/workers-app-core/reference/create-core/)
- [Configuration](/workers-app-core/guides/configuration/)
- [Database](/workers-app-core/guides/database/)
