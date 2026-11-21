import { and, eq, isNull, sql } from "drizzle-orm";
import type { Db } from "../db/client.js";
import { sessions, users, type SessionRow, type UserRow } from "../db/schema.js";
import type { Config, SessionConfig } from "../config.js";
import { isEmailAllowed, parseAllowlist } from "./allowlist.js";
import { generateRefreshToken, hashToken } from "./tokens.js";

export const REUSE_GRACE_MS = 10 * 1000;

export type NewSession = {
  sessionId: string;
  userId: string;
  refreshToken: string;
  familyExpiresAt: number;
  // The expiry of this refresh token: the absolute expiry, or the idle deadline if it comes first.
  expiresAt: number;
};

// The expiry of a session row. Without an idle timeout it is the absolute expiry of the family. With one, it is the
// earlier of the absolute expiry and the idle deadline, counted from the row's creation (the family's last refresh)
// with the current setting.
export function sessionExpiresAt(
  row: Pick<SessionRow, "familyExpiresAt" | "createdAt">,
  session: SessionConfig,
): number {
  if (session.idleTimeoutMs === null) return row.familyExpiresAt;
  return Math.min(row.familyExpiresAt, row.createdAt + session.idleTimeoutMs);
}

export async function prepareSessionValues(userId: string, config: Config, now: number) {
  const refreshToken = generateRefreshToken();
  const familyExpiresAt = now + config.session.maxAgeMs;
  const session: NewSession = {
    sessionId: crypto.randomUUID(),
    userId,
    refreshToken,
    familyExpiresAt,
    expiresAt: sessionExpiresAt({ familyExpiresAt, createdAt: now }, config.session),
  };
  const row = {
    id: session.sessionId,
    userId,
    familyId: crypto.randomUUID(),
    authMode: config.authMode,
    tokenHash: await hashToken(refreshToken),
    familyExpiresAt: session.familyExpiresAt,
    createdAt: now,
  };
  return { session, row };
}

export type PreparedSession = Awaited<ReturnType<typeof prepareSessionValues>>;

export async function prepareNewSession(db: Db, userId: string, config: Config, now: number) {
  const { session, row } = await prepareSessionValues(userId, config, now);
  return { session, insert: db.insert(sessions).values(row) };
}

// The login timestamp is updated only when that specific session was actually inserted.
export function guardedSessionStatements(
  db: D1Database, prepared: PreparedSession, guard: string, guardArgs: (string | number)[],
) {
  const { row } = prepared;
  return [
    db.prepare(`INSERT INTO sessions (id, user_id, family_id, auth_mode, token_hash, family_expires_at, created_at)
      SELECT ?, u.id, ?, ?, ?, ?, ? FROM users u WHERE u.id = ? AND ${guard}`)
      .bind(row.id, row.familyId, row.authMode, row.tokenHash, row.familyExpiresAt, row.createdAt, row.userId, ...guardArgs),
    db.prepare(`UPDATE users SET last_login_at = ?, updated_at = ?
      WHERE id = ? AND EXISTS (SELECT 1 FROM sessions WHERE id = ? AND user_id = users.id)`)
      .bind(row.createdAt, row.createdAt, row.userId, row.id),
  ];
}

// Login: insert a new session family and record the login time in one batch.
export async function issueSession(db: Db, userId: string, config: Config, now: number): Promise<NewSession> {
  const { session, insert } = await prepareNewSession(db, userId, config, now);
  await db.batch([
    insert,
    db.update(users).set({ lastLoginAt: now, updatedAt: now }).where(eq(users.id, userId)),
  ]);
  return session;
}

export function revokeFamilyQuery(db: Db, familyId: string, now: number) {
  return db
    .update(sessions)
    .set({ revokedAt: now })
    .where(and(eq(sessions.familyId, familyId), isNull(sessions.revokedAt)));
}

export function revokeUserSessionsQuery(db: Db, userId: string, now: number) {
  return db
    .update(sessions)
    .set({ revokedAt: now })
    .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)));
}

export function findSessionByTokenHash(db: Db, tokenHash: string): Promise<SessionRow | undefined> {
  return db.select().from(sessions).where(eq(sessions.tokenHash, tokenHash)).get();
}

export function findSessionById(db: Db, id: string): Promise<SessionRow | undefined> {
  return db.select().from(sessions).where(eq(sessions.id, id)).get();
}

// The two statements of a rotation (spec 6.3 step 7). Exported so tests can interleave other writes.
// db.run(sql) cannot be used in db.batch() with drizzle's D1 driver, so query builders are used.
export function rotationStatements(
  db: Db,
  params: { oldId: string; newId: string; newHash: string; now: number },
) {
  const { oldId, newId, newHash, now } = params;
  // UPDATE sessions SET rotated_at = :now, rotated_to = :new_id
  // WHERE id = :old_id AND rotated_at IS NULL AND revoked_at IS NULL
  const update = db
    .update(sessions)
    .set({ rotatedAt: now, rotatedTo: newId })
    .where(and(eq(sessions.id, oldId), isNull(sessions.rotatedAt), isNull(sessions.revokedAt)));
  // INSERT INTO sessions (all columns in table order) SELECT ...
  const insert = db.insert(sessions).select(sql`
    SELECT ${newId}, user_id, family_id, auth_mode, ${newHash}, family_expires_at, ${now}, NULL, NULL, NULL
    FROM sessions WHERE id = ${oldId} AND rotated_to = ${newId} AND revoked_at IS NULL`);
  return { update, insert };
}

export type RotationResult =
  | { ok: true; session: NewSession }
  | { ok: false; clearCookies: boolean };

const fail = (clearCookies: boolean): RotationResult => ({ ok: false, clearCookies });

export async function rotateSession(
  db: Db,
  config: Config,
  refreshToken: string,
  now: number,
): Promise<RotationResult> {
  let row = await findSessionByTokenHash(db, await hashToken(refreshToken));
  if (!row) return fail(true);

  for (let attempt = 0; ; attempt++) {
    const rejection = await checkRotatable(db, config, row, now);
    if (rejection) return rejection;

    const newId = crypto.randomUUID();
    const newRefreshToken = generateRefreshToken();
    const { update, insert } = rotationStatements(db, {
      oldId: row.id,
      newId,
      newHash: await hashToken(newRefreshToken),
      now,
    });
    const [, inserted] = await db.batch([update, insert]);
    if (inserted.meta.changes === 1) {
      return {
        ok: true,
        session: {
          sessionId: newId,
          userId: row.userId,
          refreshToken: newRefreshToken,
          familyExpiresAt: row.familyExpiresAt,
          // The new row is created at now.
          expiresAt: sessionExpiresAt({ familyExpiresAt: row.familyExpiresAt, createdAt: now }, config.session),
        },
      };
    }

    if (attempt >= 1) return fail(false);
    row = await findSessionById(db, row.id);
    if (!row) return fail(true);
  }
}

// Steps 2-6 of the rotation, then the idle timeout. Returns a failure, or null if the session may be rotated.
async function checkRotatable(
  db: Db,
  config: Config,
  row: SessionRow,
  now: number,
): Promise<RotationResult | null> {
  if (row.revokedAt !== null) return fail(true);
  if (row.familyExpiresAt <= now) return fail(true);
  if (row.authMode !== config.authMode) {
    await revokeFamilyQuery(db, row.familyId, now).run();
    return fail(true);
  }

  const user = await db.select().from(users).where(eq(users.id, row.userId)).get();
  if (!user) return fail(true);

  if (config.authMode === "oidc" && !isAllowedByConfig(config, user)) {
    await revokeFamilyQuery(db, row.familyId, now).run();
    return fail(true);
  }

  if (row.rotatedAt !== null) {
    if (now - row.rotatedAt <= REUSE_GRACE_MS) return fail(false);
    await revokeFamilyQuery(db, row.familyId, now).run();
    return fail(true);
  }
  // After the reuse check, so that a rotated token presented after the idle timeout still revokes the family. The
  // family is not revoked here: a concurrent request may have read the row before the winner rotated it.
  if (sessionExpiresAt(row, config.session) <= now) return fail(true);
  return null;
}

function isAllowedByConfig(config: Config, user: UserRow): boolean {
  return isEmailAllowed(user.email, parseAllowlist(config.oidc?.allowedEmails ?? ""));
}
