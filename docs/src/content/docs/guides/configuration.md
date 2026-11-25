---
title: Configuration
description: Variables, secrets, bindings and wrangler.jsonc settings.
---

## Variables and secrets

The mode is the `AUTH_MODE` in which a variable is used.

| name | mode | description |
| --- | --- | --- |
| `JWT_SECRET` | both | Required, at least 32 characters. |
| `AUTH_MODE` | both | `password` (default) or `oidc` |
| `APP_ORIGIN` | both | Canonical HTTPS origin of the app. Required for OIDC and for WebAuthn. |
| `PASSWORD_MFA_POLICY` | password | `optional` (default), `admins`, or `all`. An enrolled account always completes MFA on password login. |
| `PASSWORD_MFA_KEY` | password | 32 random bytes in standard base64 (generate with `openssl rand -base64 32`). Store as a Worker Secret to enable TOTP. |
| `PASSWORD_HASH_ALGORITHM` | password | Algorithm of new password hashes, `scrypt` (default) or `pbkdf2` (see [Password hashing](#password-hashing)). |
| `PASSWORD_PBKDF2_ITERATIONS` | password | PBKDF2-SHA256 iterations of new password hashes with `PASSWORD_HASH_ALGORITHM=pbkdf2`, from 10,000 to 100,000 (default 100,000; see [Password hashing](#password-hashing)). Validated with `scrypt` too: an invalid value is a configuration error. |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | oidc | The issuer, the client ID and the client secret of the app's OpenID Connect client. |
| `INITIAL_ADMIN_EMAIL` | oidc | While there are no users, the first sign-in with this email creates the first admin. Ignored once a user exists. |
| `OIDC_REQUIRE_EMAIL_VERIFIED` | oidc | `false` accepts ID tokens without `email_verified` (see [Users](/workers-app-core/guides/users/#oidc_require_email_verified)). |
| `OIDC_REQUIRE_GOOGLE_HD` | oidc | `true` requires Google's `hd` claim on the first sign-in of an address other than `@gmail.com` (see [Users](/workers-app-core/guides/users/#oidc_require_google_hd)). `false` (default) does not. |
| `SESSION_MAX_AGE_HOURS` | both | Absolute lifetime of web sessions from the sign-in, in hours (default 720 in password mode, 24 in oidc mode). |
| `SESSION_IDLE_TIMEOUT_HOURS` | both | Lifetime of web sessions from the last refresh, in hours (default: none). |

`OIDC_ISSUER` is the issuer itself (e.g. `https://idp.example.com/realms/x`). A URL that contains `/.well-known/`,
such as the URL of the discovery document, is a configuration error.

## Bindings

Bindings other than `DB` and `OAUTH_KV`:

`LOGIN_RATE_LIMITER` is an optional [Rate Limiting binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)
that limits password sign-ins (`POST /auth/login`) per email address. Without it, password sign-in has no rate limit.
The limit and period are set in `wrangler.jsonc` (requires wrangler 4.36.0 or later):

```jsonc
"ratelimits": [
  {
    "name": "LOGIN_RATE_LIMITER",
    "namespace_id": "<a positive integer unique in the account>",
    "simple": { "limit": 5, "period": 60 }
  }
]
```

## Session lifetime

`SESSION_MAX_AGE_HOURS` and `SESSION_IDLE_TIMEOUT_HOURS` are whole numbers from 1 to 9600 (400 days), written as
strings (`"168"`, not `168`, in `vars`); any other value is a configuration error. An idle timeout longer than the
max age is accepted and has no effect.

## Password hashing

`PASSWORD_HASH_ALGORITHM` is `scrypt` (the default) or `pbkdf2`, exactly; any other value is a configuration error,
in either auth mode.

| algorithm | parameters | CPU time per hash on Workers |
| --- | --- | --- |
| `scrypt` (default) | N=2^13, r=8, p=10, fixed (one of the OWASP recommendations, 8 MiB of memory) | about 150 to 200 ms |
| `pbkdf2` | PBKDF2-SHA256 with `PASSWORD_PBKDF2_ITERATIONS` iterations: 10,000 to 100,000, default 100,000 | about 17 to 56 ms at 100,000 iterations; less with fewer |

The scrypt time was measured in 2026-11 on the Paid and the Free plans.

scrypt uses `scrypt` of `node:crypto`, which needs a compatibility date of 2026-08-04 or later (or the `nodejs_compat`
flag; see [`wrangler.jsonc`](#wranglerjsonc)).

:::caution[The Free plan allows 10 ms of CPU time per request]
Both scrypt and PBKDF2 with 100,000 iterations exceed it, yet in a measurement in 2026-11 neither was cut off on the
Free plan, even at about 560 ms. Cloudflare does not guarantee this. If sign-ins fail on the CPU time limit, use
`PASSWORD_HASH_ALGORITHM=pbkdf2` with fewer `PASSWORD_PBKDF2_ITERATIONS`, or the Paid plan. Switching from scrypt to
`pbkdf2` does not lighten existing users: their scrypt hashes take the same CPU time to verify until their passwords
are set again.
:::

### PBKDF2 iterations

`PASSWORD_PBKDF2_ITERATIONS` is a whole number from 10000 to 100000, written as a string (`"50000"`, not `50000`, in
`vars`); any other value is a configuration error, in either auth mode and with either algorithm. It is used only
with `PASSWORD_HASH_ALGORITHM=pbkdf2`.

OWASP recommends 600,000 iterations for PBKDF2-SHA256, but the Web Crypto API of Cloudflare Workers rejects PBKDF2
above 100,000 iterations in production, on every plan (local `wrangler dev` accepts it, so a higher count would fail
only after deploying). The maximum and the default are therefore 100,000. A lower count takes less CPU time (see the
Free plan above).

### Changing the algorithm or the iterations

- The change applies only to hashes created afterwards: the initial setup, a user created with a password, an admin
  password reset, a password change and a password set from an invitation link.
- Existing hashes are not recomputed, on sign-in or otherwise: each hash is verified with the algorithm and
  parameters stored in it, so existing users keep signing in after a switch, and their sign-ins keep the CPU time of
  their own hashes until their passwords are set again.
- Sign-ins of unknown emails and of users without a password run a dummy verification with the configured algorithm
  and iterations.

:::caution[Accepted risk]
While existing hashes use another algorithm or other parameters, the response time differs between them, and the
response time of a sign-in can reveal which email addresses are registered. To avoid it, set the passwords of
existing users again, or keep the setting of the existing hashes (e.g. `PASSWORD_HASH_ALGORITHM=pbkdf2` for a
deployment whose users have PBKDF2 hashes).
:::

## Invalid configuration

An invalid configuration answers every request with 500 without details, and logs the names of the invalid items.
`OIDC_REQUIRE_GOOGLE_HD` is the exception: an invalid value rejects only the first association (see
[Users](/workers-app-core/guides/users/#oidc_require_google_hd)), and the rest of the app keeps working.

## `wrangler.jsonc`

`wrangler.jsonc` must have:

```jsonc
{
  // 2026-08-04 or later, which enables node:crypto (used for password hashing).
  // With an earlier date, add "nodejs_compat" to compatibility_flags.
  "compatibility_date": "2026-08-04",
  // Required for Client ID Metadata Documents: fetches of client metadata
  // must not reach internal addresses.
  "compatibility_flags": ["global_fetch_strictly_public"],
  "assets": {
    // The paths the package handles. Add the app's own paths.
    "run_worker_first": [
      "/api/*", "/auth", "/auth/*", "/authorize",
      "/mcp", "/mcp/*", "/oauth/*", "/.well-known/*"
    ]
  },
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "myapp",
      "migrations_dir": "drizzle/migrations"
    }
  ],
  "kv_namespaces": [{ "binding": "OAUTH_KV" }]
}
```
