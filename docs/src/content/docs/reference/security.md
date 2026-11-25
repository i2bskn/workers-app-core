---
title: Security behaviors
description: Cookies, session lifetimes, invitation links, revocation, headers, rate limiting and password hashing.
---

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
  `Sec-Fetch-Site: same-origin` without it). Server pages are sent with `Cache-Control: no-store` and
  `Content-Security-Policy: frame-ancestors 'none'`.
- `core.fetch` adds `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin` to every response of the
  Worker, including those of OAuthProvider, unless the response already has them. Static assets that do not go
  through the Worker (paths outside `run_worker_first`) do not get them: set the headers of assets in the app, e.g. in
  `_headers`. HSTS and redirects from HTTP to HTTPS are set in the zone settings.
- With `LOGIN_RATE_LIMITER`, each password sign-in counts against a key made from the SHA-256 hash of the normalized
  email address, before the password is checked; the client IP address is not used. Cloudflare counts per location,
  so the limit is approximate. Over the limit, the login page is answered with 429 and `Retry-After: 60`, without
  checking the password. If the binding fails, sign-in continues without a limit. Accepted risks: someone who knows an
  email address can keep its password sign-in at 429 by sending attempts over the limit, and trying one password
  against many accounts (password spraying) is not limited.
- Passwords are hashed with scrypt (N=2^13, r=8, p=10) by default, or with PBKDF2-SHA256 (100,000 iterations by
  default) with `PASSWORD_HASH_ALGORITHM=pbkdf2`, and must be 12 to 256 characters. Accepted risk: while
  `PASSWORD_HASH_ALGORITHM` or `PASSWORD_PBKDF2_ITERATIONS` differs from the setting of existing hashes, the response
  time of a password sign-in can reveal whether an email address is registered (see
  [Password hashing](/workers-app-core/guides/configuration/#password-hashing)).
- A sign-in with an unknown email runs a dummy verification that takes the same CPU time as a real one (about 150 ms
  with scrypt). `LOGIN_RATE_LIMITER` limits per email address, so attempts that change the email address each time
  are not limited and add CPU time. The same holds with PBKDF2, with less CPU time per attempt.
