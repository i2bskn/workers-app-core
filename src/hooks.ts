import type { BatchItem } from "drizzle-orm/batch";
import type { Db } from "./db/client.js";

export type CredentialsRevokedReason = "admin_reset" | "self_change" | "revoke_sessions" | "admin_mfa_reset";

export type UserDeleteStatements<DeleteData> = {
  // Run before the DELETE of the sessions and the user, in the same batch. Each must include the guard.
  statements: D1PreparedStatement[];
  // Receives the results of the statements above only, in order.
  read?(results: D1Result[]): DeleteData;
};

// Every hook is optional. Without hooks, nothing runs besides the package's own statements.
export type CoreHooks<AppBindings, DeleteData> = {
  // Authorize an initial OIDC identity association before writing the user. "link" is the first sign-in of an
  // invited user (registered beforehand, not linked yet); "create" is only the creation of the first admin by
  // INITIAL_ADMIN_EMAIL. Linked identities and uninvited emails skip this hook.
  beforeOidcUserLinkOrCreate?(args: {
    operation: "link" | "create";
    env: AppBindings;
    db: Db;
    issuer: string;
    subject: string;
    email: string;
    claims: Readonly<Record<string, unknown>>;
  }): Promise<boolean>;
  // Appended after the INSERT of a user, in the same batch: the initial setup, the first OIDC sign-in of
  // INITIAL_ADMIN_EMAIL, and POST /api/v1/users. The INSERT of the setup and of the first admin may insert nothing,
  // so each statement must guard itself with EXISTS (SELECT 1 FROM users WHERE id = ?).
  userCreatedStatements?(d1: D1Database, userId: string, now: number): D1PreparedStatement[];
  // Called right before a web session is issued or rotated on sign-in: password login, the sign-in after accepting
  // an invitation, the OIDC callback, POST /auth/refresh and GET /auth/login with a valid refresh cookie. An exception
  // fails the request with 500.
  beforeSessionIssued?(args: { env: AppBindings; db: Db; userId: string; now: number }): Promise<void>;
  // Statements in the batch that deletes a user. guard binds the user ID as ?1; app statements must include it,
  // bind the user ID as ?1 and may use ?2 and on for their own values.
  userDeleteStatements?(args: {
    db: Db;
    d1: D1Database;
    userId: string;
    guard: string;
  }): Promise<UserDeleteStatements<DeleteData>>;
  // After the delete batch succeeded, before the MCP grants are revoked. Exceptions are logged and ignored.
  afterUserDeleted?(args: { env: AppBindings; userId: string; data: DeleteData }): Promise<void>;
  // Statements in the batch that revokes the credentials of a user (password reset or change, session revocation,
  // MFA reset by an admin), after the revocation of the sessions.
  credentialsRevokedStatements?(args: {
    db: Db;
    userId: string;
    now: number;
    reason: CredentialsRevokedReason;
  }): BatchItem<"sqlite">[];
};
