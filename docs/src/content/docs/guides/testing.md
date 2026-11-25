---
title: Testing
description: Test helpers for @cloudflare/vitest-plugin.
---

```ts
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { createTestHelpers } from "@i2bskn/workers-app-core/testing";
import worker from "../src/index";

export const { send, login, createUser, resetDb, sessionCookies } =
  createTestHelpers({
    worker,
    env,
    createExecutionContext,
    waitOnExecutionContext,
    brandId: "myapp",
    origin: "https://myapp.test",
  });
```

`createUser({ email, role, password, hashConfig })` hashes the password with scrypt, like the default configuration.
scrypt is slow by design, so tests that create many users take longer; `hashConfig: { algorithm: "pbkdf2",
iterations: 100000 }` creates a PBKDF2 hash instead.

`resetDb(appTables)` deletes the given tables (children first), then `sessions`, `user_invitations` and `users`. Also:
`setCookies`, `dbChangingBefore`, `d1With`, `d1RecordingLargeBinds`, `countTable`, and the constants `PASSWORD`,
`TEST_JWT_SECRET` and `D1_MAX_BOUND_VALUES`.
