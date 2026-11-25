---
title: Database
description: Re-export the core tables and own the migrations.
---

Re-export the core tables (`users`, `sessions`, `user_invitations` and the password MFA tables) from the app's
Drizzle schema. Generate and apply the app's schema migration before deploying a version that queries the new tables.
When upgrading a password-mode app that re-exports only `users` and `sessions`, use the export below, run
`drizzle-kit generate`, apply the generated migration to D1, then deploy the Worker. Password sign-in checks the MFA
tables even under the default optional policy.

```ts
export * from "@i2bskn/workers-app-core/schema";
```

Apps own their migrations; the package ships none. `createDb(d1)` is `drizzle(d1)` without a schema (`db.query.*` is
not available), and `db.$client` is the D1 binding.
