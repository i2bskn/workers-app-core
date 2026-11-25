---
title: Browser client
description: The browser-safe fetch with token refresh and the user management API functions.
---

`@i2bskn/workers-app-core/client` imports no server module, so it can be bundled into the browser app.
`createApiFetch` makes the fetch for `hc()`: on 401 it refreshes the tokens once and sends the same request again,
and if it still gets 401, it moves to the login page and rejects with `LoginRequiredError`.

```ts
import { hc } from "hono/client";
import { createApiFetch } from "@i2bskn/workers-app-core/client";
import type { AppType } from "../src/app";

export const apiFetch = createApiFetch({
  fetch: (input, init) => fetch(input, init),
  redirectToLogin: (url) => window.location.assign(url),
  currentPath: () => window.location.pathname + window.location.search,
});
export const client = hc<AppType>("/", { fetch: apiFetch });
```

## User management API

The functions for the user management API (`/api/v1/users`) take that fetch:

```ts
import { createUser, listUsers } from "@i2bskn/workers-app-core/client";

const result = await createUser(apiFetch, {
  email: "alice@example.com",
  role: "member",
});
if (result.kind === "ok" && result.invitation) showLink(result.invitation.url);
```

| function | request |
| --- | --- |
| `listUsers(fetch)` | `GET /api/v1/users` |
| `createUser(fetch, input)` | `POST /api/v1/users` |
| `changeUserRole(fetch, userId, role)` | `PATCH /api/v1/users/:id` |
| `resetUserPassword(fetch, userId, password)` | `POST /api/v1/users/:id/password` (password mode only) |
| `reissueUserInvitation(fetch, userId)` | `POST /api/v1/users/:id/invitation` (password mode only) |
| `resetUserMfa(fetch, userId)` | `POST /api/v1/users/:id/reset-mfa` (password mode only) |
| `revokeUserSessions(fetch, userId)` | `POST /api/v1/users/:id/revoke-sessions` |
| `deleteUser(fetch, userId)` | `DELETE /api/v1/users/:id` |

- Pass the same `createApiFetch` instance that the app gives to `hc()`. Each instance has its own shared refresh and
  its own once-only move to the login page; a second instance does not share them.
- The fetch must come from this package's `createApiFetch`: `redirecting` is detected with `instanceof
  LoginRequiredError` of this package. A plain fetch also works, but 401 is then returned as an `error`.
- None of the functions rejects. The result is `{ kind: "ok", ... }` or one of:
  - `error`: an error response, with the server's message (`responseErrorMessage`), or an ok response whose body is
    not in the expected shape. 404 is also an `error` for `listUsers` and `createUser`.
  - `notFound`: 404 for the functions that take a user ID. In oidc mode, the password-only functions also get 404,
    which cannot be told apart from a missing user.
  - `unknown`: no response (the fetch rejected), so the request may have succeeded on the server. For `listUsers`, a
    GET, this only means that the server could not be reached: show a connection error.
  - `redirecting`: the move to the login page has started.
- `createUser` returns the user and the invitation separately: `invitation` is set only in password mode when no
  password was given, and `null` otherwise. `listUsers` returns `auth_mode` as `authMode`.
- A user ID that is not 1 to 64 letters, digits, `_` or `-` is not sent, and the result is
  `{ kind: "error", message: "ユーザーが見つかりません" }`.
