---
title: Upgrading
description: Breaking changes by version.
---

## 0.6.0

- New password hashes use scrypt instead of PBKDF2 by default (see `PASSWORD_HASH_ALGORITHM`). The package imports
  `node:crypto`, so every app needs a compatibility date of 2026-08-04 or later (or the `nodejs_compat` flag), even
  with `PASSWORD_HASH_ALGORITHM=pbkdf2`. scrypt takes about 150 to 200 ms of CPU time per hash, over the 10 ms of
  the Free plan (see [Password hashing](/workers-app-core/guides/configuration/#password-hashing)).
- Existing PBKDF2 hashes keep working and are not recomputed. In a deployment with existing users, the response time
  of a sign-in can reveal which email addresses are registered until their passwords are set again (see
  [Password hashing](/workers-app-core/guides/configuration/#password-hashing)).
- `Config` has a new required field, `passwordHash` (`PasswordHashConfig`).
- `createUser` of the testing helpers creates scrypt hashes by default, which can make an app's tests slower. Pass
  `hashConfig: { algorithm: "pbkdf2", iterations: 100000 }` to create a PBKDF2 hash instead.

## 0.5.0

- An `OIDC_ISSUER` that contains `/.well-known/` is a configuration error. Set the issuer itself, not the URL of its
  discovery document.
- `core.fetch` adds `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin` to the responses of the
  Worker (a value the response already has is kept). HTML pages served by the Worker no longer send a Referer to other
  sites, and browsers no longer load JS, CSS and other files served by the Worker unless their Content-Type is right.
  A response that needs another value keeps the header that its route sets.

## 0.4.0

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

## 0.3.0

- Password sign-in reads the MFA tables, even under the default `optional` policy. Before deploying, re-export the
  core tables (`export * from "@i2bskn/workers-app-core/schema"`), run `drizzle-kit generate`, and apply the
  migration to D1.

## 0.2.0

- `issueSession` takes a `Config` instead of an `AuthMode`; it can no longer create a session of another mode than
  the configuration.
- `Config` has a required `session: SessionConfig` (`{ maxAgeMs, idleTimeoutMs }`).
- `NewSession` has a required `expiresAt`, and `setCookiesForSession` computes the Max-Age of the refresh cookie from
  it instead of `familyExpiresAt`.
