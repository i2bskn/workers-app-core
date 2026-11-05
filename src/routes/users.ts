import { Hono } from "hono";
import { and, asc, eq, sql } from "drizzle-orm";
import type {
  CreateUserInput,
  CreateUserRequest,
  ResetPasswordRequest,
  UpdateUserRequest,
  UserList,
} from "../api-types.js";
import { clock } from "../clock.js";
import type { CoreBindings } from "../config.js";
import { users } from "../db/schema.js";
import { apiError, describeError, type CoreEnv, type CoreMiddleware } from "../auth/middleware.js";
import { hashPassword } from "../auth/password.js";
import { revokeUserSessionsQuery } from "../auth/sessions.js";
import { deleteUser, findUserById, isUserUniqueViolation, runUserInsert } from "../auth/users.js";
import { isRole, isValidPassword, normalizeEmail, normalizeName } from "../auth/validate.js";
import type { CoreHooks } from "../hooks.js";
import { revokeAllGrants } from "../mcp/grants.js";
import { jsonBody, toApiUser } from "./api.js";

const userNotFound = "ユーザーが見つかりません";

const createUserBody = jsonBody<CreateUserRequest, CreateUserInput, CoreEnv>((body, c) => {
  const email = normalizeEmail(body.email);
  if (email === null) return apiError(c, 400, "invalid_email", "メールアドレスの形式が正しくありません");
  const name = normalizeName(body.name);
  if (!name.ok) return apiError(c, 400, "invalid_name", "名前は 100 文字以下の文字列にしてください");
  if (!isValidPassword(body.password)) {
    return apiError(c, 400, "invalid_password", "パスワードは 12 文字以上 256 文字以下にしてください");
  }
  if (!isRole(body.role)) return apiError(c, 400, "invalid_role", "ロールは admin または member です");
  return { ok: true, value: { email, name: name.value, password: body.password, role: body.role } };
});

const resetPasswordBody = jsonBody<ResetPasswordRequest, ResetPasswordRequest, CoreEnv>((body, c) => {
  if (!isValidPassword(body.password)) {
    return apiError(c, 400, "invalid_password", "パスワードは 12 文字以上 256 文字以下にしてください");
  }
  return { ok: true, value: { password: body.password } };
});

const updateUserBody = jsonBody<UpdateUserRequest, UpdateUserRequest, CoreEnv>((body, c) => {
  if (!isRole(body.role)) return apiError(c, 400, "invalid_role", "ロールは admin または member です");
  return { ok: true, value: { role: body.role } };
});

export type UsersRoutesDeps = {
  middleware: CoreMiddleware;
  hooks: CoreHooks<CoreBindings, unknown>;
};

export function createUsersRoutes({ middleware, hooks }: UsersRoutesDeps) {
  const { requireAdmin, requireMode, requireUser } = middleware;
  return new Hono<CoreEnv>()
    .get("/", requireUser, requireAdmin, async (c) => {
      const rows = await c.get("db").select().from(users).orderBy(asc(users.createdAt), asc(users.id)).all();
      const body: UserList = { users: rows.map(toApiUser), auth_mode: c.get("config").authMode };
      return c.json(body, 200);
    })
    .post("/", requireMode("password"), requireUser, requireAdmin, createUserBody, async (c) => {
      const input = c.req.valid("json");
      const db = c.get("db");
      const now = clock.now();
      const id = crypto.randomUUID();
      const passwordHash = await hashPassword(input.password);
      const d1 = db.$client;
      try {
        const insert = d1
          .prepare(
            `INSERT INTO users (id, email, name, role, password_hash, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(id, input.email, input.name, input.role, passwordHash, now, now);
        await runUserInsert(d1, insert, id, now, hooks.userCreatedStatements);
      } catch (error) {
        if (isUserUniqueViolation(error)) {
          return apiError(c, 409, "email_taken", "このメールアドレスはすでに使われています");
        }
        throw error;
      }
      const user = await findUserById(db, id);
      if (!user) throw new Error("created user not found");
      return c.json(toApiUser(user), 201);
    })
    .post("/:id/password", requireMode("password"), requireUser, requireAdmin, resetPasswordBody, async (c) => {
      const input = c.req.valid("json");
      const db = c.get("db");
      const id = c.req.param("id");
      if (!(await findUserById(db, id))) return apiError(c, 404, "not_found", userNotFound);

      // MCP grants first: if KV fails, D1 is unchanged and the request can be retried.
      // OAUTH_PROVIDER is absent only on origins that cannot issue grants.
      if (c.env.OAUTH_PROVIDER) await revokeAllGrants(c.env.OAUTH_PROVIDER, id);
      const passwordHash = await hashPassword(input.password);
      // Taken after hashing, right before the batch, so that mcp_revoked_at covers the grants authorized meanwhile.
      const now = clock.now();
      const extra = hooks.credentialsRevokedStatements?.({ db, userId: id, now, reason: "admin_reset" }) ?? [];
      // mcp_revoked_at is set with or without OAUTH_PROVIDER: it rejects at /mcp the tokens authorized until now,
      // including grants that revokeAllGrants missed because the KV listing lags behind.
      await db.batch([
        db.update(users).set({ passwordHash, mcpRevokedAt: now, updatedAt: now }).where(eq(users.id, id)),
        revokeUserSessionsQuery(db, id, now),
        ...extra,
      ]);
      return c.body(null, 204);
    })
    .post("/:id/revoke-sessions", requireUser, requireAdmin, async (c) => {
      const db = c.get("db");
      const id = c.req.param("id");
      if (!(await findUserById(db, id))) return apiError(c, 404, "not_found", userNotFound);
      // MCP grants first: if KV fails, D1 is unchanged and the request can be retried. mcp_revoked_at is set with
      // or without OAUTH_PROVIDER, in the same batch as the sessions.
      if (c.env.OAUTH_PROVIDER) await revokeAllGrants(c.env.OAUTH_PROVIDER, id);
      const now = clock.now();
      const extra = hooks.credentialsRevokedStatements?.({ db, userId: id, now, reason: "revoke_sessions" }) ?? [];
      await db.batch([
        db.update(users).set({ mcpRevokedAt: now }).where(eq(users.id, id)),
        revokeUserSessionsQuery(db, id, now),
        ...extra,
      ]);
      return c.body(null, 204);
    })
    .patch("/:id", requireUser, requireAdmin, updateUserBody, async (c) => {
      const input = c.req.valid("json");
      const db = c.get("db");
      const id = c.req.param("id");
      const target = await findUserById(db, id);
      if (!target) return apiError(c, 404, "not_found", userNotFound);
      if (target.role === input.role) return c.json(toApiUser(target), 200);

      const now = clock.now();
      if (input.role === "admin") {
        await db.update(users).set({ role: "admin", updatedAt: now }).where(eq(users.id, id)).run();
      } else {
        const result = await db
          .update(users)
          .set({ role: "member", updatedAt: now })
          .where(
            and(
              eq(users.id, id),
              eq(users.role, "admin"),
              sql`(SELECT COUNT(*) FROM users WHERE role = 'admin') > 1`,
            ),
          )
          .run();
        if (result.meta.changes === 0) {
          const current = await findUserById(db, id);
          if (!current) return apiError(c, 404, "not_found", userNotFound);
          if (current.role === "admin") {
            return apiError(c, 409, "last_admin", "最後の管理者のロールは変更できません");
          }
          return c.json(toApiUser(current), 200);
        }
      }

      const updated = await findUserById(db, id);
      if (!updated) return apiError(c, 404, "not_found", userNotFound);
      return c.json(toApiUser(updated), 200);
    })
    .delete("/:id", requireUser, requireAdmin, async (c) => {
      const id = c.req.param("id");
      // An admin cannot lock themselves out; another admin can delete them.
      if (id === c.get("user").id) return apiError(c, 400, "cannot_delete_self", "自分自身は削除できません");
      const result = await deleteUser(c.get("db"), id, hooks.userDeleteStatements);
      if (!result.ok) {
        if (result.error === "not_found") return apiError(c, 404, "not_found", userNotFound);
        return apiError(c, 409, "last_admin", "最後の管理者は削除できません");
      }

      // Side effects of the app, best effort: the user is already gone.
      if (hooks.afterUserDeleted) {
        try {
          await hooks.afterUserDeleted({ env: c.env, userId: id, data: result.data });
        } catch (error) {
          console.error("after user delete hook failed", { userId: id, ...describeError(error) });
        }
      }
      // After D1, best effort. A grant left by a KV failure cannot be used: the MCP handler rejects a user
      // who no longer exists.
      try {
        if (c.env.OAUTH_PROVIDER) await revokeAllGrants(c.env.OAUTH_PROVIDER, id);
      } catch (error) {
        console.error("grant revocation after user delete failed", { userId: id, ...describeError(error) });
      }
      return c.body(null, 204);
    });
}
