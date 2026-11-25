---
title: Hooks
description: Optional hooks that add statements and checks to the core's flows.
---

Every hook is optional; without hooks only the package's own statements run.

## `userCreatedStatements`

`userCreatedStatements(d1, userId, now): D1PreparedStatement[]`: appended after the INSERT of a user in the same
`d1.batch`, at the initial setup, the first OIDC sign-in of `INITIAL_ADMIN_EMAIL` (the creation of the first admin)
and `POST /api/v1/users`. The INSERTs of the setup and of the first admin are
`INSERT ... WHERE NOT EXISTS (SELECT 1 FROM users)` and may insert nothing when two sign-ins race, so each
statement must guard itself with `EXISTS (SELECT 1 FROM users WHERE id = ?)`. Success is still decided by the
INSERT. `d1` is `db.$client`. A UNIQUE violation in your statements fails the request with 500; only a violation
of the `users` table itself is answered as a duplicate (`email_taken`, or a retry on the OIDC path).

## `beforeOidcUserLinkOrCreate`

`beforeOidcUserLinkOrCreate({ operation, env, db, issuer, subject, email, claims })`: after the ID token checks,
authorize the first association with an OIDC identity. `operation` is `"link"` for the first sign-in of a user
registered beforehand (an invitation), and `"create"` only for the creation of the first admin by
`INITIAL_ADMIN_EMAIL`. Return `true` to allow it, or `false` for a 403 before the user write or session
issuance. An exception fails the request with 500. The hook receives the normalized email and the verified token
claims. Already linked issuer/subject pairs skip this hook, including when the email changes, and so do emails
that are not invited (they get a 403 without any write). The check of `OIDC_REQUIRE_GOOGLE_HD` runs before this
hook, which is not called when that check rejects (including for an invalid value). Concurrent sign-ins can cause
a retry: use this hook for checks, and commit one-time effects atomically with the user write.

## `beforeSessionIssued`

`beforeSessionIssued({ env, db, userId, now })`: called right before a web session is issued or rotated on sign-in:
password login (after all required factors), the sign-in after accepting an invitation link (likewise), the OIDC
callback (after the user is resolved), `POST /auth/refresh` and
`GET /auth/login` with a valid refresh cookie (after the rotation, before the cookies). Not called on the setup, or
when a concurrent rotation already won. An exception fails the request with 500 and sets no cookies.
On the two refresh paths the rotation is already stored when the hook runs, so a failing hook leaves the browser
with the previous refresh cookie: a retry within the reuse grace (10 seconds) is answered 401 without ending the
session, and a retry after it is treated as token reuse and ends the session family. Keep the hook idempotent and
make it fail only on real errors.

## `userDeleteStatements`

`userDeleteStatements({ db, d1, userId, guard })`: returns `{ statements, read? }`, called after the checks for an
unknown user and the last admin. The statements run first in the batch that deletes the sessions and the user.
`guard` is the SQL that refuses the delete if the user is gone or is the last admin when the batch runs: every
statement must include it. The guard binds the user ID as `?1`, so bind the user ID as `?1` and use `?2` and on for
your own values. Success is decided by the final `DELETE FROM users ... RETURNING id`. `read(results)` receives the
results of your statements only, in order, and its value is passed to `afterUserDeleted` as `data`.

## `afterUserDeleted`

`afterUserDeleted({ env, userId, data })`: after the delete batch succeeded, before the user's MCP grants are
revoked. Exceptions are logged and ignored; the grants are still revoked.

## `credentialsRevokedStatements`

`credentialsRevokedStatements({ db, userId, now, reason })`: drizzle query builders added to the batch that revokes
credentials, after the revocation of the sessions. `reason` is `admin_reset` (an admin sets a password),
`self_change` (the user changes their password; the statements run before the new session is inserted),
`revoke_sessions` or `admin_mfa_reset` (an admin resets the user's MFA; the statements run before the MFA factors
are deleted, so the MFA rows still exist). The MCP grants in KV are revoked before the batch.
