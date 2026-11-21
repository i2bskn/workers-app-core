import type { Db } from "../db/client.js";
import { findUserById } from "./users.js";
import { generateRefreshToken, hashToken } from "./tokens.js";

// Invitation links of password mode. A user without a password (password_hash IS NULL) gets a token; opening the
// link lets them set their password. Only the hash of the token is stored, and the token is shown once.

export const INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export const INVITATION_PATH = "/auth/invite";

export type IssuedInvitation = { token: string; tokenHash: string; expiresAt: number };

// A new random token, as strong as a refresh token.
export async function newInvitation(now: number): Promise<IssuedInvitation> {
  const token = generateRefreshToken();
  return { token, tokenHash: await hashToken(token), expiresAt: now + INVITATION_TTL_MS };
}

export function invitationUrl(origin: string, token: string): string {
  return `${origin}${INVITATION_PATH}?token=${encodeURIComponent(token)}`;
}

// The INSERT of the token of a user created in the same batch. Fails the batch if the user already has one.
export function insertInvitationStatement(
  d1: D1Database,
  userId: string,
  invitation: IssuedInvitation,
  now: number,
): D1PreparedStatement {
  return d1
    .prepare("INSERT INTO user_invitations (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)")
    .bind(userId, invitation.tokenHash, invitation.expiresAt, now);
}

// Replaces the token of a user who has not set a password yet. Returns false, without writing, when the user is gone
// or already has a password.
export async function replaceInvitation(
  d1: D1Database,
  userId: string,
  invitation: IssuedInvitation,
  now: number,
): Promise<boolean> {
  const result = await d1
    .prepare(`
    INSERT INTO user_invitations (user_id, token_hash, expires_at, created_at)
    SELECT ?1, ?2, ?3, ?4
    WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1 AND password_hash IS NULL)
    ON CONFLICT(user_id) DO UPDATE SET
      token_hash = excluded.token_hash, expires_at = excluded.expires_at, created_at = excluded.created_at`)
    .bind(userId, invitation.tokenHash, invitation.expiresAt, now)
    .run();
  return result.meta.changes === 1;
}

export type ValidInvitation = { userId: string; email: string; tokenHash: string };

// The invitation of a token: the hash matches, it has not expired, and the user has not set a password.
export async function findValidInvitation(db: Db, token: string, now: number): Promise<ValidInvitation | null> {
  if (token === "") return null;
  const tokenHash = await hashToken(token);
  const row = await db.$client
    .prepare("SELECT user_id, expires_at FROM user_invitations WHERE token_hash = ?")
    .bind(tokenHash)
    .first<{ user_id: string; expires_at: number }>();
  if (!row || row.expires_at <= now) return null;
  const user = await findUserById(db, row.user_id);
  if (!user || user.passwordHash !== null) return null;
  return { userId: user.id, email: user.email, tokenHash };
}

// Sets the password and consumes the token in one batch. Only the first statement decides: it changes the user only
// if the token still matches, has not expired, and no password is set. The DELETE removes only the matching token.
// Returns false when the invitation was no longer valid (e.g. used by a concurrent request).
export async function acceptInvitation(
  d1: D1Database,
  params: { userId: string; tokenHash: string; passwordHash: string; now: number },
): Promise<boolean> {
  const { userId, tokenHash, passwordHash, now } = params;
  const [update] = await d1.batch([
    d1
      .prepare(`UPDATE users SET password_hash = ?, updated_at = ?
      WHERE id = ? AND password_hash IS NULL
        AND EXISTS (SELECT 1 FROM user_invitations WHERE user_id = ? AND token_hash = ? AND expires_at > ?)`)
      .bind(passwordHash, now, userId, userId, tokenHash, now),
    d1.prepare("DELETE FROM user_invitations WHERE user_id = ? AND token_hash = ?").bind(userId, tokenHash),
  ]);
  return update?.meta.changes === 1;
}
