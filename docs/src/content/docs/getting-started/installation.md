---
title: Installation
description: Install the package and its peer dependencies.
---

```sh
pnpm add @i2bskn/workers-app-core \
  hono drizzle-orm zod openid-client \
  @cloudflare/workers-oauth-provider \
  @modelcontextprotocol/sdk \
  @cfworker/json-schema
```

The app shares its peer dependencies with the core. The core installs its WebAuthn verifier (`@simplewebauthn/server`) and TOTP QR encoder (`uqr`) as runtime dependencies.

The package imports `node:crypto`, so the app needs a compatibility date of 2026-08-04 or later (or the
`nodejs_compat` flag). See [`wrangler.jsonc`](/workers-app-core/guides/configuration/#wranglerjsonc) for the
settings the app must have.

Next: [wire the core into the app](/workers-app-core/getting-started/usage/).
