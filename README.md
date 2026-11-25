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

## Documentation

https://docs.i2bskn.com/workers-app-core/

- [Usage](https://docs.i2bskn.com/workers-app-core/getting-started/usage/)
- [Configuration](https://docs.i2bskn.com/workers-app-core/guides/configuration/)
- [`createCore` options](https://docs.i2bskn.com/workers-app-core/reference/create-core/)
- [Security behaviors](https://docs.i2bskn.com/workers-app-core/reference/security/)
- [Upgrading](https://docs.i2bskn.com/workers-app-core/reference/upgrading/) (breaking changes by version)

The source of the documentation is in [`docs/`](docs/).

## License

MIT
