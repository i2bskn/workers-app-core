---
title: Users
description: The first admin, adding users, and OIDC sign-in by invitation.
---

## Password mode

In password mode, the first admin is created on the initial setup page (`/auth/setup`), which is open only while
there are no users: complete it right after deploying. Admins then add users with `POST /api/v1/users`, either with
an initial password, or without one to get an invitation link (see
[Security behaviors](/workers-app-core/reference/security/)).

## OIDC mode

In oidc mode, sign-in is by invitation. While there are no users, the first sign-in with `INITIAL_ADMIN_EMAIL`
creates the first admin; without `INITIAL_ADMIN_EMAIL`, nobody can sign in to an empty deployment (logged as
`initial_admin_not_configured`). Admins register users with `POST /api/v1/users` (an email and a role, no password).
Only registered emails can sign in for the first time: the email of the ID token must match the registered user,
whose OIDC `iss` and `sub` are then linked to it. Later sign-ins identify the user by `iss` and `sub`, and the email
is not compared again. Other emails get a 403, and no user or session is created. Deleting a user who has not
signed in yet withdraws the invitation; deleting a user who has signed in stops them (their sessions and MCP grants
end too). An invalid `INITIAL_ADMIN_EMAIL` is a configuration error.

### `OIDC_REQUIRE_EMAIL_VERIFIED`

`OIDC_REQUIRE_EMAIL_VERIFIED=false` accepts ID tokens without `email_verified` (a claim that is present must still
be `true`). Use it only when the IdP guarantees verified emails by other means: if the IdP lets someone sign in with
an email they have not verified, they can be linked to an invited user or to `INITIAL_ADMIN_EMAIL` and take over
that account.

### `OIDC_REQUIRE_GOOGLE_HD`

`OIDC_REQUIRE_GOOGLE_HD=true` requires a non-blank `hd` claim (the domain of a Google Workspace account) for any
email other than a `@gmail.com` address. It is checked only on the first association: the linking of an invited
user and the creation of the first admin. Linked users are not checked again. The value of `hd` is not compared
with the email, so that the Workspace of a partner is accepted too. The issuer is not checked: enable it only when
the IdP signs in with Google alone, either Google itself or Cloudflare Access for SaaS with Google as its only login
method, passing Google's `hd` as a claim of the same name (do not make that claim required: Gmail accounts have no
`hd`). A rejection returns 403 and is logged as `google_hd_missing`. The value is `true` or `false` (default); any
other value rejects the linking and the creation of the first admin with 403 and logs `invalid configuration`.
