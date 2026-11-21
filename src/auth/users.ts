import { and, eq, isNull, sql } from "drizzle-orm";
import type { Db } from "../db/client.js";
import { mfaAccounts, users, type UserRow } from "../db/schema.js";
import type { CoreHooks } from "../hooks.js";
import { revokeUserSessionsQuery } from "./sessions.js";

type UserCreatedStatements = CoreHooks<unknown, unknown>["userCreatedStatements"];

export function isUniqueViolation(error: unknown): boolean {
  for (let e: unknown = error; e instanceof Error; e = e.cause) {
    if (e.message.includes("UNIQUE constraint failed")) return true;
  }
  return false;
}

// A UNIQUE violation of the users table itself (e.g. "UNIQUE constraint failed: users.email"). Used where the INSERT of
// a user shares a batch with statements of userCreatedStatements, so that a violation in those statements is not taken
// for a duplicate user.
export function isUserUniqueViolation(error: unknown): boolean {
  for (let e: unknown = error; e instanceof Error; e = e.cause) {
    if (/UNIQUE constraint failed: users\./.test(e.message)) return true;
  }
  return false;
}

export function findUserById(db: Db, id: string): Promise<UserRow | undefined> {
  return db.select().from(users).where(eq(users.id, id)).get();
}

export function findUserByEmail(db: Db, email: string): Promise<UserRow | undefined> {
  return db.select().from(users).where(eq(users.email, email)).get();
}

// Both password-change routes apply the same credential and session updates in their D1 batch.
export function changePasswordStatements(db: Db, userId: string, passwordHash: string, now: number) {
  return [
    db.update(users).set({ passwordHash, mcpRevokedAt: now, updatedAt: now }).where(eq(users.id, userId)),
    revokeUserSessionsQuery(db, userId, now),
    db.update(mfaAccounts).set({ totpAttempts: 0, totpRetryAt: 0 }).where(eq(mfaAccounts.userId, userId)),
  ] as const;
}

export async function countUsers(db: Db): Promise<number> {
  const row = await db.select({ count: sql<number>`COUNT(*)` }).from(users).get();
  return row?.count ?? 0;
}

// Runs the INSERT of a user, followed by `following` (statements of the package that must commit with the user, e.g.
// the invitation token) and the statements of the userCreatedStatements hook, in the same batch. Without other
// statements, the INSERT runs alone as before. Returns the number of rows the INSERT changed.
export async function runUserInsert(
  d1: D1Database,
  insert: D1PreparedStatement,
  userId: string,
  now: number,
  userCreatedStatements: UserCreatedStatements,
  following: D1PreparedStatement[] = [],
): Promise<number> {
  const extra = userCreatedStatements?.(d1, userId, now) ?? [];
  if (following.length === 0 && extra.length === 0) return (await insert.run()).meta.changes;
  const results = await d1.batch([insert, ...following, ...extra]);
  return results[0]?.meta.changes ?? 0;
}

// Creates the first admin only when there are no users, in one statement.
// Returns null if a user already exists.
export async function createInitialAdmin(
  db: Db,
  params: { email: string; name: string | null; passwordHash: string; now: number },
  userCreatedStatements?: UserCreatedStatements,
): Promise<UserRow | null> {
  const id = crypto.randomUUID();
  const { email, name, passwordHash, now } = params;
  const d1 = db.$client;
  const insert = d1
    .prepare(`
    INSERT INTO users (id, email, name, role, password_hash, oidc_issuer, oidc_subject, created_at, updated_at, last_login_at)
    SELECT ?, ?, ?, 'admin', ?, NULL, NULL, ?, ?, NULL
    WHERE NOT EXISTS (SELECT 1 FROM users)`)
    .bind(id, email, name, passwordHash, now, now);
  const changes = await runUserInsert(d1, insert, id, now, userCreatedStatements);
  if (changes !== 1) return null;
  return (await findUserById(db, id)) ?? null;
}

export type OidcIdentity = {
  issuer: string;
  subject: string;
  email: string;
  name: string | null;
};

type AllowOidcUserWrite = (operation: "link" | "create") => Promise<boolean>;

export type ResolveOidcUserOptions = {
  // The normalized INITIAL_ADMIN_EMAIL, or null when unset.
  initialAdminEmail?: string | null;
  userCreatedStatements?: UserCreatedStatements;
  allowWrite?: AllowOidcUserWrite;
};

export type OidcUserResult =
  | { ok: true; user: UserRow }
  | { ok: false; reason: "conflict" | "not_allowed" | "not_invited" | "failed" };

// Maps an OIDC identity to a user. Only users registered beforehand (invitations: users without an OIDC subject) are
// linked on their first sign-in, and the first admin is created only for INITIAL_ADMIN_EMAIL while there are no users.
// Anyone else is not_invited, and nothing is written.
export async function resolveOidcUser(
  db: Db,
  identity: OidcIdentity,
  now: number,
  options: ResolveOidcUserOptions = {},
): Promise<OidcUserResult> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const result = await tryResolveOidcUser(db, identity, now, options);
    if (result !== "retry") return result;
  }
  return { ok: false, reason: "failed" };
}

async function tryResolveOidcUser(
  db: Db,
  identity: OidcIdentity,
  now: number,
  options: ResolveOidcUserOptions,
): Promise<OidcUserResult | "retry"> {
  const { issuer, subject, email, name } = identity;
  const { initialAdminEmail = null, userCreatedStatements, allowWrite } = options;

  const linked = await db
    .select()
    .from(users)
    .where(and(eq(users.oidcIssuer, issuer), eq(users.oidcSubject, subject)))
    .get();
  if (linked) {
    if (linked.email === email) return { ok: true, user: linked };
    try {
      await db.update(users).set({ email, updatedAt: now }).where(eq(users.id, linked.id)).run();
      return { ok: true, user: { ...linked, email, updatedAt: now } };
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      console.warn("oidc email update skipped: email is used by another user", { userId: linked.id });
      return { ok: true, user: linked };
    }
  }

  const byEmail = await findUserByEmail(db, email);
  if (byEmail) {
    if (byEmail.oidcSubject !== null) return { ok: false, reason: "conflict" };
    // An invitation: link the identity. The role, name and creation time stay as registered.
    if (allowWrite && !(await allowWrite("link"))) return { ok: false, reason: "not_allowed" };
    try {
      const result = await db
        .update(users)
        .set({ oidcIssuer: issuer, oidcSubject: subject, updatedAt: now })
        .where(and(eq(users.id, byEmail.id), isNull(users.oidcSubject)))
        .run();
      if (result.meta.changes !== 1) return "retry";
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      return "retry";
    }
    const user = await findUserById(db, byEmail.id);
    return user ? { ok: true, user } : "retry";
  }

  if (initialAdminEmail === null || email !== initialAdminEmail || (await countUsers(db)) > 0) {
    return { ok: false, reason: "not_invited" };
  }
  if (allowWrite && !(await allowWrite("create"))) return { ok: false, reason: "not_allowed" };

  const id = crypto.randomUUID();
  const d1 = db.$client;
  try {
    const insert = d1
      .prepare(`
      INSERT INTO users (id, email, name, role, password_hash, oidc_issuer, oidc_subject, created_at, updated_at, last_login_at)
      SELECT ?, ?, ?, 'admin', NULL, ?, ?, ?, ?, NULL
      WHERE NOT EXISTS (SELECT 1 FROM users)`)
      .bind(id, email, name, issuer, subject, now, now);
    // Another user was created meanwhile: the retry finds the linked user or rejects.
    if ((await runUserInsert(d1, insert, id, now, userCreatedStatements)) !== 1) return "retry";
  } catch (error) {
    if (!isUserUniqueViolation(error)) throw error;
    return "retry";
  }
  const user = await findUserById(db, id);
  return user ? { ok: true, user } : "retry";
}

export type DeleteUserResult<DeleteData = undefined> =
  | { ok: true; data: DeleteData }
  | { ok: false; error: "not_found" | "last_admin" };

// Every statement of the delete batch carries this guard, so that nothing is deleted if the user is gone or is the
// last admin when the batch runs. Binds the user ID as ?1.
export const DELETE_USER_GUARD = `EXISTS (SELECT 1 FROM users WHERE id = ?1
    AND (role = 'member' OR (SELECT COUNT(*) FROM users WHERE role = 'admin') > 1))`;

// Deletes the user and their sessions. The users statement stays last: its result decides success.
export async function deleteUser<DeleteData = undefined>(
  db: Db,
  id: string,
  userDeleteStatements?: CoreHooks<unknown, DeleteData>["userDeleteStatements"],
): Promise<DeleteUserResult<DeleteData>> {
  const target = await findUserById(db, id);
  if (!target) return { ok: false, error: "not_found" };
  if (target.role === "admin") {
    const row = await db.select({ count: sql<number>`COUNT(*)` }).from(users).where(eq(users.role, "admin")).get();
    if ((row?.count ?? 0) <= 1) return { ok: false, error: "last_admin" };
  }

  // The check above is only a fast path; the guard decides. The batch is one transaction.
  const guard = DELETE_USER_GUARD;
  const d1 = db.$client;
  const app = userDeleteStatements ? await userDeleteStatements({ db, d1, userId: id, guard }) : { statements: [] };
  const results = await d1.batch([
    ...app.statements,
    d1.prepare(`DELETE FROM sessions WHERE user_id = ?1 AND ${guard}`).bind(id),
    d1.prepare(`DELETE FROM users WHERE id = ?1 AND ${guard} RETURNING id`).bind(id),
  ]);

  // meta.changes counts cascaded rows too, so success is decided by the row returned by the users statement.
  if ((results.at(-1)?.results.length ?? 0) === 0) {
    return (await findUserById(db, id)) ? { ok: false, error: "last_admin" } : { ok: false, error: "not_found" };
  }
  const data = app.read ? app.read(results.slice(0, app.statements.length)) : undefined;
  return { ok: true, data: data as DeleteData };
}
