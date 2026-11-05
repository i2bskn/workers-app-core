import { and, eq, isNull, sql } from "drizzle-orm";
import type { Db } from "../db/client.js";
import { users, type UserRow } from "../db/schema.js";
import type { CoreHooks } from "../hooks.js";

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

export async function countUsers(db: Db): Promise<number> {
  const row = await db.select({ count: sql<number>`COUNT(*)` }).from(users).get();
  return row?.count ?? 0;
}

// Runs the INSERT of a user, followed by the statements of the userCreatedStatements hook in the same batch.
// Without statements, the INSERT runs alone as before. Returns the number of rows the INSERT changed.
export async function runUserInsert(
  d1: D1Database,
  insert: D1PreparedStatement,
  userId: string,
  now: number,
  userCreatedStatements: UserCreatedStatements,
): Promise<number> {
  const extra = userCreatedStatements?.(d1, userId, now) ?? [];
  if (extra.length === 0) return (await insert.run()).meta.changes;
  const results = await d1.batch([insert, ...extra]);
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

export type OidcUserResult =
  | { ok: true; user: UserRow }
  | { ok: false; reason: "conflict" | "failed" };

// Maps an OIDC identity to a user, creating one just in time (spec 6.6).
export async function resolveOidcUser(
  db: Db,
  identity: OidcIdentity,
  now: number,
  userCreatedStatements?: UserCreatedStatements,
): Promise<OidcUserResult> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const result = await tryResolveOidcUser(db, identity, now, userCreatedStatements);
    if (result !== "retry") return result;
  }
  return { ok: false, reason: "failed" };
}

async function tryResolveOidcUser(
  db: Db,
  identity: OidcIdentity,
  now: number,
  userCreatedStatements: UserCreatedStatements,
): Promise<OidcUserResult | "retry"> {
  const { issuer, subject, email, name } = identity;

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

  const id = crypto.randomUUID();
  const d1 = db.$client;
  try {
    const insert = d1
      .prepare(`
      INSERT INTO users (id, email, name, role, password_hash, oidc_issuer, oidc_subject, created_at, updated_at, last_login_at)
      SELECT ?, ?, ?, CASE WHEN EXISTS (SELECT 1 FROM users) THEN 'member' ELSE 'admin' END,
        NULL, ?, ?, ?, ?, NULL`)
      .bind(id, email, name, issuer, subject, now, now);
    await runUserInsert(d1, insert, id, now, userCreatedStatements);
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
