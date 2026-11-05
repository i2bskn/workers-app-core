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
