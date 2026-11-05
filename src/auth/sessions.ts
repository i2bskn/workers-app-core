import { and, eq, isNull, sql } from "drizzle-orm";
import type { Db } from "../db/client.js";
import { sessions, users, type SessionRow, type UserRow } from "../db/schema.js";
import type { AuthMode, Config } from "../config.js";
import { isEmailAllowed, parseAllowlist } from "./allowlist.js";
import { generateRefreshToken, hashToken } from "./tokens.js";

const DAY_MS = 24 * 60 * 60 * 1000;
export const FAMILY_LIFETIME_MS: Record<AuthMode, number> = {
  password: 30 * DAY_MS,
  oidc: DAY_MS,
};
export const REUSE_GRACE_MS = 10 * 1000;

export type NewSession = {
  sessionId: string;
  userId: string;
  refreshToken: string;
  familyExpiresAt: number;
};

export async function prepareNewSession(db: Db, userId: string, mode: AuthMode, now: number) {
  const refreshToken = generateRefreshToken();
  const session: NewSession = {
    sessionId: crypto.randomUUID(),
    userId,
    refreshToken,
    familyExpiresAt: now + FAMILY_LIFETIME_MS[mode],
  };
  const insert = db.insert(sessions).values({
    id: session.sessionId,
    userId,
    familyId: crypto.randomUUID(),
    authMode: mode,
    tokenHash: await hashToken(refreshToken),
    familyExpiresAt: session.familyExpiresAt,
    createdAt: now,
  });
  return { session, insert };
}

// Login: insert a new session family and record the login time in one batch.
export async function issueSession(db: Db, userId: string, mode: AuthMode, now: number): Promise<NewSession> {
  const { session, insert } = await prepareNewSession(db, userId, mode, now);
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
        },
      };
    }

    if (attempt >= 1) return fail(false);
    row = await findSessionById(db, row.id);
    if (!row) return fail(true);
  }
}

// Steps 2-6 of the rotation. Returns a failure, or null if the session may be rotated.
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
  return null;
}

function isAllowedByConfig(config: Config, user: UserRow): boolean {
  return isEmailAllowed(user.email, parseAllowlist(config.oidc?.allowedEmails ?? ""));
}
