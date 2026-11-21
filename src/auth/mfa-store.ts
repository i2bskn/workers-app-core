import { generateRefreshToken, hashToken } from "./tokens.js";
import { guardedSessionStatements, type PreparedSession } from "./sessions.js";
import type { PasswordMfaConfig } from "../config.js";
import type { MfaCredential } from "./webauthn.js";

export const MFA_PENDING_SECONDS = 5 * 60;
const ATTEMPTS_PER_FLOW = 5;

type Purpose = "login" | "manage" | "enroll" | "disable";

export type MfaPending = {
  userId: string;
  email: string;
  next: string;
  purpose: Purpose;
  revision: number;
  replace: boolean;
  setup: boolean;
  didUseRecoveryCode: boolean;
  challenge: string | null;
  totpSecret: string | null;
};

export type MfaFactors = {
  revision: number;
  totp: { secret: string; lastStep: number } | null;
  credentials: MfaCredential[];
};

type MfaPolicy = PasswordMfaConfig["policy"];

// Each caller aliases the current users row as u. Unknown policies require MFA.
function optionalMfaForUser(policy: MfaPolicy | undefined): string {
  if (policy === "optional") return "1";
  if (policy === "admins") return "u.role = 'member'";
  return "0";
}

export async function getMfaLoginState(db: D1Database, userId: string, policy: MfaPolicy) {
  const row = await db.prepare(`SELECT COALESCE(a.revision, 0) AS revision,
    NOT (${optionalMfaForUser(policy)}) AS required
    FROM users u LEFT JOIN mfa_accounts a ON a.user_id = u.id WHERE u.id = ?`)
    .bind(userId).first<{ revision: number; required: number }>();
  return row && { revision: row.revision, required: row.required === 1 };
}

export async function cancelMfa(db: D1Database, token: string): Promise<void> {
  await db.prepare("DELETE FROM mfa_pending WHERE token_hash = ?").bind(await hashToken(token)).run();
}

export async function getMfaFactors(db: D1Database, userId: string): Promise<MfaFactors> {
  const [accountRows, keyRows] = await db.batch([
    db.prepare("SELECT revision, totp_secret, totp_last_step FROM mfa_accounts WHERE user_id = ?").bind(userId),
    db.prepare("SELECT id, public_key, counter, transports FROM mfa_credentials WHERE user_id = ?").bind(userId),
  ]);
  const account = accountRows!.results[0] as
    | { revision: number; totp_secret: string | null; totp_last_step: number }
    | undefined;
  const keys = keyRows!.results as { id: string; public_key: string; counter: number; transports: string | null }[];
  return {
    revision: account?.revision ?? 0,
    totp: account?.totp_secret ? { secret: account.totp_secret, lastStep: account.totp_last_step } : null,
    credentials: keys.map((key) => ({
      id: key.id,
      publicKey: key.public_key,
      counter: key.counter,
      transports: key.transports === null ? undefined : JSON.parse(key.transports),
    })),
  };
}

// Every read or mutation of a pending flow checks the *current* password and factor revision.
const live = `
  p.token_hash = ?1 AND p.expires_at > ?2
  AND EXISTS (SELECT 1 FROM users u WHERE u.id = p.user_id AND u.password_hash = p.password_hash)
  AND EXISTS (SELECT 1 FROM mfa_accounts a WHERE a.user_id = p.user_id AND a.revision = p.revision)`;

// Used by statements that follow a guarded UPDATE inside the same D1 batch. The unique marker
// makes every subsequent statement a no-op if the guard lost a race.
const markedUser = "(SELECT user_id FROM mfa_pending WHERE token_hash = ?1 AND marker = ?2)";

export async function beginMfa(db: D1Database, input: {
  userId: string; passwordHash: string; next: string; purpose: Purpose; revision: number; policy: MfaPolicy; now: number;
  replace?: boolean; setup?: boolean;
}): Promise<string | null> {
  const { userId, passwordHash, purpose, revision, next, now } = input;
  if ((input.setup && purpose !== "enroll") || (input.replace && purpose !== "manage")) return null;
  // Only a first-time enrollee may start enrollment using just a password. A subsequent change
  // has to go through a manage flow and prove a previously registered factor.
  if ((revision === 0) !== (purpose === "enroll")) return null;
  const token = generateRefreshToken();
  const tokenHash = await hashToken(token);
  const [, , inserted] = await db.batch([
    db.prepare("DELETE FROM mfa_pending WHERE expires_at <= ?").bind(now),
    db.prepare(`INSERT INTO mfa_accounts (user_id)
      SELECT id FROM users WHERE id = ? AND password_hash = ? ON CONFLICT(user_id) DO NOTHING`)
      .bind(userId, passwordHash),
    db.prepare(`INSERT INTO mfa_pending
      (token_hash, user_id, password_hash, revision, purpose, next, expires_at, replace_factors, initial_setup)
      SELECT ?, u.id, u.password_hash, a.revision, ?, ?, ?, ?, ?
      FROM users u JOIN mfa_accounts a ON a.user_id = u.id
      WHERE u.id = ? AND u.password_hash = ? AND a.revision = ?
      ${purpose === "disable" ? `AND (${optionalMfaForUser(input.policy)})` : ""}`)
      .bind(tokenHash, purpose, next, now + MFA_PENDING_SECONDS * 1000, input.replace ? 1 : 0, input.setup ? 1 : 0,
        userId, passwordHash, revision),
  ]);
  return inserted!.meta.changes === 1 ? token : null;
}

export async function readMfa(db: D1Database, token: string, now: number): Promise<MfaPending | null> {
  const row = await db.prepare(`SELECT p.user_id AS userId, u.email, p.next, p.purpose, p.revision,
    p.replace_factors AS replaceFlag, p.initial_setup AS setupFlag, (p.recovery_hash IS NOT NULL) AS recoveryFlag, p.challenge, p.totp_secret AS totpSecret
    FROM mfa_pending p JOIN users u ON u.id = p.user_id WHERE ${live}`)
    .bind(await hashToken(token), now)
    .first<Omit<MfaPending, "replace" | "setup" | "didUseRecoveryCode"> & { replaceFlag: number; setupFlag: number; recoveryFlag: number }>();
  if (!row) return null;
  const { replaceFlag, setupFlag, recoveryFlag, ...pending } = row;
  return { ...pending, replace: replaceFlag === 1, setup: setupFlag === 1, didUseRecoveryCode: recoveryFlag === 1 };
}

export async function setMfaChallenge(db: D1Database, token: string, now: number, challenge: string): Promise<boolean> {
  const changed = await db.prepare(`UPDATE mfa_pending AS p SET challenge = ?3 WHERE ${live}`)
    .bind(await hashToken(token), now, challenge).run();
  return changed.meta.changes === 1;
}

export async function saveMfaTotpSecret(db: D1Database, token: string, now: number, secret: string): Promise<string | null> {
  return db.prepare(`UPDATE mfa_pending AS p SET totp_secret = COALESCE(totp_secret, ?3)
    WHERE ${live} AND p.purpose = 'enroll' RETURNING totp_secret`)
    .bind(await hashToken(token), now, secret).first<string>("totp_secret");
}

// Every attempt is bounded by its own flow. Only guesses against a registered TOTP also
// share a budget across flows, so a different browser can still use a passkey or recovery code.
export async function reserveMfaAttempt(
  db: D1Database, token: string, now: number, method?: "totp",
): Promise<boolean> {
  const tokenHash = await hashToken(token);
  if (method !== "totp") {
    const claimed = await db.prepare(`UPDATE mfa_pending AS p SET attempts = attempts + 1
      WHERE ${live} AND p.attempts < ?3`).bind(tokenHash, now, ATTEMPTS_PER_FLOW).run();
    return claimed.meta.changes === 1;
  }

  const marker = crypto.randomUUID();
  const [claimed] = await db.batch([
    db.prepare(`UPDATE mfa_pending AS p SET attempts = attempts + 1, marker = ?3
      WHERE ${live} AND p.attempts < ?4 AND p.purpose <> 'enroll' AND EXISTS (SELECT 1 FROM mfa_accounts a
        WHERE a.user_id = p.user_id AND a.totp_secret IS NOT NULL
        AND a.totp_retry_at <= ?2)`)
      .bind(tokenHash, now, marker, ATTEMPTS_PER_FLOW),
    db.prepare(`UPDATE mfa_accounts SET
      totp_attempts = totp_attempts + 1,
      totp_retry_at = CASE
        WHEN totp_attempts + 1 >= 20 THEN ?3 + 86400000
        WHEN totp_attempts + 1 >= 15 THEN ?3 + 14400000
        WHEN totp_attempts + 1 >= 10 THEN ?3 + 1800000
        WHEN totp_attempts + 1 >= 5 THEN ?3 + 300000
        ELSE 0 END
      WHERE user_id = ${markedUser}`).bind(tokenHash, marker, now),
  ]);
  return claimed!.meta.changes === 1;
}

export type MfaProof =
  | { kind: "totp"; step: number }
  | { kind: "webauthn"; id: string; counter: number; challenge: string }
  | { kind: "recovery"; hash: string };

export async function issuePasswordOnlySession(
  db: D1Database, prepared: PreparedSession, verifiedHash: string, policy: MfaPolicy,
): Promise<boolean> {
  const guard = `u.password_hash = ? AND (${optionalMfaForUser(policy)})
    AND NOT EXISTS (SELECT 1 FROM mfa_accounts a WHERE a.user_id = u.id AND a.revision > 0)`;
  const [insert] = await db.batch(guardedSessionStatements(db, prepared, guard, [verifiedHash]));
  return insert!.meta.changes === 1;
}

type Outcome = "session" | "enroll";
type Guard = { sql: string; args: (string | number)[] };

function verificationGuard(proof: MfaProof, policy: MfaPolicy | undefined): Guard {
  // A promotion while the confirmation page is open must prevent disabling required MFA.
  const purpose = `p.purpose IN ('login','manage') OR (p.purpose = 'disable' AND EXISTS
    (SELECT 1 FROM users u WHERE u.id = p.user_id AND (${optionalMfaForUser(policy)})))`;
  const guard = `${live} AND (${purpose}) AND `;
  switch (proof.kind) {
    case "totp":
      return { sql: guard + `EXISTS (SELECT 1 FROM mfa_accounts a WHERE a.user_id = p.user_id
        AND a.totp_secret IS NOT NULL AND a.totp_last_step < ?3)`, args: [proof.step] };
    case "webauthn":
      return { sql: guard + `p.challenge = ?3 AND EXISTS (SELECT 1 FROM mfa_credentials k
        WHERE k.user_id = p.user_id AND k.id = ?4 AND (k.counter < ?5 OR (k.counter = 0 AND ?5 = 0)))`,
        args: [proof.challenge, proof.id, proof.counter] };
    case "recovery":
      return { sql: guard + `EXISTS (SELECT 1 FROM mfa_recovery_codes r
        WHERE r.user_id = p.user_id AND r.hash = ?3)`, args: [proof.hash] };
  }
}

function verificationOutcome(proof: MfaProof, replaceOnRecovery: boolean) {
  // Reserve the last code for device replacement. Check the number in the same batch as consumption.
  let enroll = "p.purpose = 'manage'";
  if (proof.kind === "recovery") {
    const last = "NOT EXISTS (SELECT 1 FROM mfa_recovery_codes r WHERE r.user_id = p.user_id AND r.hash <> ?3)";
    enroll += ` OR (p.purpose = 'login' AND ${replaceOnRecovery ? "1" : last})`;
  }
  return `CASE WHEN ${enroll} THEN 'enroll' ELSE 'session' END`;
}

export async function checkMfaVerification(
  db: D1Database, token: string, now: number, proof: MfaProof, policy: MfaPolicy | undefined, replaceOnRecovery: boolean,
): Promise<Outcome | null> {
  const guard = verificationGuard(proof, policy);
  return db.prepare(`SELECT ${verificationOutcome(proof, replaceOnRecovery)} AS outcome
    FROM mfa_pending p WHERE ${guard.sql}`).bind(await hashToken(token), now, ...guard.args).first<Outcome>("outcome");
}

function markFlow(db: D1Database, guard: Guard, tokenHash: string, now: number, marker: string, sessionUserId: string | null) {
  const args = [tokenHash, now, ...guard.args];
  let condition = guard.sql;
  if (sessionUserId !== null) {
    args.push(sessionUserId);
    condition += ` AND p.user_id = ?${args.length}`;
  }
  return db.prepare(`UPDATE mfa_pending AS p SET marker = ?${args.length + 1} WHERE ${condition}`)
    .bind(...args, marker);
}

function markedSession(db: D1Database, session: PreparedSession, tokenHash: string, marker: string) {
  return guardedSessionStatements(db, session,
    "EXISTS (SELECT 1 FROM mfa_pending p WHERE p.user_id = u.id AND p.token_hash = ? AND p.marker = ?)",
    [tokenHash, marker]);
}

export async function finishMfaVerification(
  db: D1Database, token: string, now: number, proof: MfaProof, policy: MfaPolicy | undefined,
  options: { outcome: "session"; replaceOnRecovery: boolean; session: PreparedSession }
    | { outcome: "enroll"; replaceOnRecovery: boolean },
): Promise<boolean> {
  const { outcome, replaceOnRecovery } = options;
  const tokenHash = await hashToken(token);
  const marker = crypto.randomUUID();
  const guard = verificationGuard(proof, policy);
  guard.sql += ` AND ${verificationOutcome(proof, replaceOnRecovery)} = ?${guard.args.length + 3}`;
  guard.args.push(outcome);
  const sessionUserId = options.outcome === "session" ? options.session.row.userId : null;
  const stmts = [markFlow(db, guard, tokenHash, now, marker, sessionUserId)];
  if (options.outcome === "session") stmts.push(...markedSession(db, options.session, tokenHash, marker));
  switch (proof.kind) {
    case "totp":
      stmts.push(db.prepare(`UPDATE mfa_accounts SET totp_last_step = ?3 WHERE user_id = ${markedUser}`)
        .bind(tokenHash, marker, proof.step));
      break;
    case "webauthn":
      stmts.push(db.prepare(`UPDATE mfa_credentials SET counter = ?4 WHERE user_id = ${markedUser} AND id = ?3`)
        .bind(tokenHash, marker, proof.id, proof.counter));
      break;
    case "recovery":
      if (outcome === "session") {
        stmts.push(db.prepare(`DELETE FROM mfa_recovery_codes WHERE user_id = ${markedUser} AND hash = ?3`)
          .bind(tokenHash, marker, proof.hash));
      }
      break;
  }
  if (proof.kind !== "recovery" || outcome === "session") {
    stmts.push(db.prepare(`UPDATE mfa_accounts SET totp_attempts = 0, totp_retry_at = 0
      WHERE user_id = ${markedUser}`).bind(tokenHash, marker));
  }
  if (outcome === "enroll") {
    // An abandoned registration must leave the recovery code usable. The final registration batch consumes it.
    stmts.push(db.prepare(`UPDATE mfa_pending SET purpose = 'enroll', challenge = NULL, totp_secret = NULL,
      replace_factors = CASE WHEN purpose = 'login' THEN 1 ELSE replace_factors END,
      recovery_hash = ?3, marker = NULL, attempts = 0 WHERE token_hash = ?1 AND marker = ?2`)
      .bind(tokenHash, marker, proof.kind === "recovery" ? proof.hash : null));
  } else {
    stmts.push(db.prepare(`DELETE FROM mfa_accounts WHERE user_id = (
      SELECT user_id FROM mfa_pending WHERE token_hash = ?1 AND marker = ?2 AND purpose = 'disable')`)
      .bind(tokenHash, marker),
      db.prepare("DELETE FROM mfa_pending WHERE token_hash = ? AND marker = ?").bind(tokenHash, marker));
  }
  const [claimed] = await db.batch(stmts);
  return claimed!.meta.changes === 1;
}

export type MfaEnrollment =
  | { kind: "totp"; secret: string; step: number }
  | { kind: "webauthn"; credential: MfaCredential; challenge: string };

function enrollmentGuard(factor: MfaEnrollment, replace: boolean): Guard {
  const guard = `${live} AND p.purpose = 'enroll' AND p.replace_factors = ?3
    AND (p.recovery_hash IS NULL OR EXISTS (SELECT 1 FROM mfa_recovery_codes r
      WHERE r.user_id = p.user_id AND r.hash = p.recovery_hash)) AND `;
  const flag = replace ? 1 : 0;
  if (factor.kind === "totp") {
    return { sql: guard + `p.totp_secret = ?4 AND (p.replace_factors = 1 OR EXISTS (
      SELECT 1 FROM mfa_accounts a WHERE a.user_id = p.user_id AND a.totp_secret IS NULL))`,
      args: [flag, factor.secret] };
  }
  return { sql: guard + "p.challenge = ?4 AND NOT EXISTS (SELECT 1 FROM mfa_credentials WHERE id = ?5)",
    args: [flag, factor.challenge, factor.credential.id] };
}

export async function checkMfaEnrollment(
  db: D1Database, token: string, now: number, factor: MfaEnrollment, replace: boolean,
): Promise<boolean> {
  const guard = enrollmentGuard(factor, replace);
  return !!await db.prepare(`SELECT 1 FROM mfa_pending p WHERE ${guard.sql}`)
    .bind(await hashToken(token), now, ...guard.args).first();
}

export async function finishMfaEnrollment(db: D1Database, token: string, now: number, factor: MfaEnrollment,
  recoveryHashes: string[], replace: boolean, session: PreparedSession): Promise<boolean> {
  const tokenHash = await hashToken(token);
  const marker = crypto.randomUUID();
  const guard = enrollmentGuard(factor, replace);
  guard.sql += ` AND (p.revision = 0 OR p.replace_factors = 1 OR p.recovery_hash IS NOT NULL) = ?${guard.args.length + 3}`;
  guard.args.push(recoveryHashes.length ? 1 : 0);
  const stmts = [
    markFlow(db, guard, tokenHash, now, marker, session.row.userId),
    ...markedSession(db, session, tokenHash, marker),
  ];
  if (recoveryHashes.length > 0) {
    stmts.push(db.prepare(`DELETE FROM mfa_recovery_codes WHERE user_id = ${markedUser}`).bind(tokenHash, marker));
  }
  if (replace) {
    stmts.push(db.prepare(`DELETE FROM mfa_credentials WHERE user_id = ${markedUser}`).bind(tokenHash, marker),
      db.prepare(`UPDATE mfa_accounts SET totp_secret = NULL, totp_last_step = -1 WHERE user_id = ${markedUser}`)
        .bind(tokenHash, marker));
  }
  if (factor.kind === "totp") {
    stmts.push(db.prepare(`UPDATE mfa_accounts SET totp_secret = ?3, totp_last_step = ?4
      WHERE user_id = ${markedUser}`).bind(tokenHash, marker, factor.secret, factor.step));
  } else {
    const key = factor.credential;
    stmts.push(db.prepare(`INSERT INTO mfa_credentials (id, user_id, public_key, counter, transports)
      SELECT ?3, user_id, ?4, ?5, ?6 FROM mfa_pending WHERE token_hash = ?1 AND marker = ?2`)
      .bind(tokenHash, marker, key.id, key.publicKey, key.counter, key.transports ? JSON.stringify(key.transports) : null));
  }
  for (const hash of recoveryHashes) {
    stmts.push(db.prepare(`INSERT INTO mfa_recovery_codes (hash, user_id)
      SELECT ?3, user_id FROM mfa_pending WHERE token_hash = ?1 AND marker = ?2`).bind(tokenHash, marker, hash));
  }
  stmts.push(db.prepare(`UPDATE mfa_accounts SET revision = revision + 1, totp_attempts = 0, totp_retry_at = 0
    WHERE user_id = ${markedUser}`).bind(tokenHash, marker),
    db.prepare("DELETE FROM mfa_pending WHERE token_hash = ? AND marker = ?").bind(tokenHash, marker));
  const [claimed] = await db.batch(stmts);
  return claimed!.meta.changes === 1;
}
