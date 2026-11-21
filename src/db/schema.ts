import { sql } from "drizzle-orm";
import { check, index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const users = sqliteTable(
  "users",
  {
    id: text("id").primaryKey(),
    email: text("email").notNull().unique(),
    name: text("name"),
    role: text("role", { enum: ["admin", "member"] }).notNull(),
    passwordHash: text("password_hash"),
    oidcIssuer: text("oidc_issuer"),
    oidcSubject: text("oidc_subject"),
    createdAt: integer("created_at").notNull(),
    updatedAt: integer("updated_at").notNull(),
    lastLoginAt: integer("last_login_at"),
    // Set when the password changes or the sessions are revoked. The MCP handler rejects the tokens authorized at
    // or before this time, including grants that the revocation in KV missed. NULL when never set.
    mcpRevokedAt: integer("mcp_revoked_at"),
  },
  (t) => [
    uniqueIndex("users_oidc_issuer_subject_unique").on(t.oidcIssuer, t.oidcSubject),
    check("users_role_check", sql`${t.role} IN ('admin', 'member')`),
  ],
);

export const sessions = sqliteTable(
  "sessions",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    familyId: text("family_id").notNull(),
    authMode: text("auth_mode", { enum: ["oidc", "password"] }).notNull(),
    tokenHash: text("token_hash").notNull().unique(),
    familyExpiresAt: integer("family_expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
    rotatedAt: integer("rotated_at"),
    rotatedTo: text("rotated_to"),
    revokedAt: integer("revoked_at"),
  },
  (t) => [
    index("sessions_user_id_idx").on(t.userId),
    index("sessions_family_id_idx").on(t.familyId),
    check("sessions_auth_mode_check", sql`${t.authMode} IN ('oidc', 'password')`),
  ],
);

export type UserRow = typeof users.$inferSelect;
export type SessionRow = typeof sessions.$inferSelect;

// Invitation tokens of password mode: a user without a password sets one through the link. One token per user;
// issuing another replaces it. Only the hash of the token is stored.
export const userInvitations = sqliteTable("user_invitations", {
  userId: text("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  tokenHash: text("token_hash").notNull().unique(),
  expiresAt: integer("expires_at").notNull(),
  createdAt: integer("created_at").notNull(),
});

export type UserInvitationRow = typeof userInvitations.$inferSelect;

export const mfaAccounts = sqliteTable("mfa_accounts", {
  userId: text("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  // Bumped only when the set of factors changes. Old challenges must not accept a different set.
  revision: integer("revision").notNull().default(0),
  totpSecret: text("totp_secret"),
  totpLastStep: integer("totp_last_step").notNull().default(-1),
  totpAttempts: integer("totp_attempts").notNull().default(0),
  totpRetryAt: integer("totp_retry_at").notNull().default(0),
});

export const mfaCredentials = sqliteTable("mfa_credentials", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull().references(() => mfaAccounts.userId, { onDelete: "cascade" }),
  publicKey: text("public_key").notNull(),
  counter: integer("counter").notNull(),
  transports: text("transports"),
}, (t) => [index("mfa_credentials_user_idx").on(t.userId)]);

export const mfaRecoveryCodes = sqliteTable("mfa_recovery_codes", {
  hash: text("hash").primaryKey(),
  userId: text("user_id").notNull().references(() => mfaAccounts.userId, { onDelete: "cascade" }),
}, (t) => [index("mfa_recovery_codes_user_idx").on(t.userId)]);

export const mfaPending = sqliteTable("mfa_pending", {
  tokenHash: text("token_hash").primaryKey(),
  userId: text("user_id").notNull().references(() => mfaAccounts.userId, { onDelete: "cascade" }),
  passwordHash: text("password_hash").notNull(),
  revision: integer("revision").notNull(),
  purpose: text("purpose", { enum: ["login", "manage", "enroll", "disable"] }).notNull(),
  replace: integer("replace_factors", { mode: "boolean" }).notNull().default(false),
  setup: integer("initial_setup", { mode: "boolean" }).notNull().default(false),
  next: text("next").notNull(),
  expiresAt: integer("expires_at").notNull(),
  attempts: integer("attempts").notNull().default(0),
  challenge: text("challenge"),
  totpSecret: text("totp_secret"),
  recoveryHash: text("recovery_hash"),
  // A successful guarded write tags the row; only that write's batch may apply its effects.
  marker: text("marker"),
}, (t) => [
  index("mfa_pending_expiry_idx").on(t.expiresAt),
  index("mfa_pending_user_idx").on(t.userId),
]);
