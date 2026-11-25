---
title: Password MFA
description: Passkeys, security keys and authenticator apps for password mode.
---

## Enabling MFA

Configure `APP_ORIGIN` to offer WebAuthn passkeys and security keys. Set `PASSWORD_MFA_KEY` to also offer
authenticator apps (TOTP). Keep this encryption key stable and backed up independently of `JWT_SECRET`.
Changing it makes existing TOTP secrets unreadable; users can recover with an unused recovery code.
A required policy needs at least one configured enrollment method. In password mode, an unsupported
`APP_ORIGIN` disables WebAuthn. When WebAuthn is the only method, open initial setup at the configured origin.
Each pending sign-in or registration allows five verification attempts. Unsuccessful checks of an already
registered TOTP also introduce an account-wide delay for that method. After attempts 5, 10,
15 and 20, the minimum interval increases to 5 minutes, 30 minutes, 4 hours and 24 hours respectively.
Successful authentication, a password change, or an administrator password reset clears this delay.
A user can still start a fresh flow with a passkey or recovery code while TOTP is waiting.

## Enrolling and recovery

Users can enroll from the password login or visit `/auth/mfa/manage`. Adding or replacing an enrolled factor
requires the password and an existing factor or recovery code. A user who has lost both their factors and their
recovery codes needs an admin to reset their MFA (see [Admin reset](#admin-reset)). The same checks apply when
disabling voluntary MFA. Store the single-use recovery codes away from the authenticator. On the recovery form, users
can choose to replace a lost device. Using the last code starts replacement automatically. The code remains
valid until registration completes, so users can restart an interrupted registration. To replace a registered
passkey, use another authenticator or TOTP. The existing credentials work until the replacement is confirmed. Adding or replacing
a factor using a recovery code issues a new set of codes. A password reset preserves the account's factors.
`admins` requires enrollment for administrators, and `all` for everyone, including the first admin at setup.
Each fresh password sign-in applies the current policy before issuing a session. Enabling MFA does not revoke
existing web sessions or MCP grants, and refreshing their tokens does not prompt for a second factor.
OIDC applications use their identity provider's MFA policy.

## Admin reset

An admin resets another user's MFA with `POST /api/v1/users/:id/reset-mfa` (password mode only; 404 in oidc mode).
It deletes all of the user's factors (passkeys, TOTP and recovery codes) and any MFA flow in progress, revokes their
web sessions and MCP grants, and keeps their password. It answers 204, 409 `mfa_not_enrolled` for a user without
MFA, and 400 `cannot_reset_own_mfa` for the requesting admin: admins change their own factors at
`/auth/mfa/manage`, and another admin resets a locked-out admin. After the reset, a user whom the policy requires to
use MFA enrolls a new factor at the next password sign-in.

:::caution
At that point the password alone is enough to enroll, so anyone who knows the password could enroll first: confirm
the user's identity before resetting, and ask them to sign in and enroll right away.
:::

If the password may have leaked with the device (e.g. a stolen device), reset the
password as well with `POST /api/v1/users/:id/password`. An admin who resets both a user's password and MFA can
enroll new factors and sign in as that user, so MFA does not protect users against admins.

## When the only admin is locked out

When the only admin has lost their factors and recovery codes, the deployer deletes the MFA rows in D1 directly,
child tables first so that the result does not depend on foreign key behavior:

```sh
wrangler d1 execute <DATABASE> --remote --command "
DELETE FROM mfa_pending
  WHERE user_id = (SELECT id FROM users WHERE email = 'admin@example.com');
DELETE FROM mfa_recovery_codes
  WHERE user_id = (SELECT id FROM users WHERE email = 'admin@example.com');
DELETE FROM mfa_credentials
  WHERE user_id = (SELECT id FROM users WHERE email = 'admin@example.com');
DELETE FROM mfa_accounts
  WHERE user_id = (SELECT id FROM users WHERE email = 'admin@example.com');
"
```

`users.email` stores the normalized (lowercase) address. This does not revoke sessions or MCP grants; if needed,
the admin can revoke their own sessions with `POST /api/v1/users/:id/revoke-sessions` after signing in.
