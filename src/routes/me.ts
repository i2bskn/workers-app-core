import { Hono } from "hono";
import { eq } from "drizzle-orm";
import type { ChangeMyPasswordRequest } from "../api-types.js";
import type { BrandNames } from "../brand.js";
import { clock } from "../clock.js";
import type { CoreBindings } from "../config.js";
import { users } from "../db/schema.js";
import { setCookiesForSession } from "../auth/cookies.js";
import { apiError, type CoreEnv, type CoreMiddleware } from "../auth/middleware.js";
import { hashPassword, verifyPassword } from "../auth/password.js";
import { prepareNewSession, revokeUserSessionsQuery } from "../auth/sessions.js";
import { isValidPassword } from "../auth/validate.js";
import type { CoreHooks } from "../hooks.js";
import { revokeAllGrants } from "../mcp/grants.js";
import { jsonBody, toApiUser } from "./api.js";

const changeMyPasswordBody = jsonBody<ChangeMyPasswordRequest, ChangeMyPasswordRequest, CoreEnv>((body, c) => {
  if (typeof body.current_password !== "string") {
    return apiError(c, 400, "invalid_current_password", "現在のパスワードを指定してください");
  }
  if (!isValidPassword(body.new_password)) {
    return apiError(c, 400, "invalid_new_password", "新しいパスワードは 12 文字以上 256 文字以下にしてください");
  }
  return { ok: true, value: { current_password: body.current_password, new_password: body.new_password } };
});

export type MeRoutesDeps = {
  names: BrandNames;
  middleware: CoreMiddleware;
  hooks: CoreHooks<CoreBindings, unknown>;
};

export function createMeRoutes({ names, middleware, hooks }: MeRoutesDeps) {
  const { requireMode, requireUser } = middleware;
  return new Hono<CoreEnv>()
    .get("/", requireUser, (c) => c.json(toApiUser(c.get("user")), 200))
    .post("/password", requireMode("password"), requireUser, changeMyPasswordBody, async (c) => {
      const input = c.req.valid("json");
      const user = c.get("user");
      if (user.passwordHash === null) {
        return apiError(c, 400, "password_not_set", "パスワードが設定されていません");
      }
      if (!(await verifyPassword(input.current_password, user.passwordHash))) {
        return apiError(c, 400, "invalid_current_password", "現在のパスワードが違います");
      }

      // All MCP grants are revoked, unlike sessions, where the current one is kept. KV first: if it fails, D1 is
      // unchanged and the request can be retried.
      if (c.env.OAUTH_PROVIDER) await revokeAllGrants(c.env.OAUTH_PROVIDER, user.id);
      const db = c.get("db");
      const config = c.get("config");
      const passwordHash = await hashPassword(input.new_password);
      // Taken after hashing, right before the batch, so that mcp_revoked_at covers the grants authorized meanwhile.
      const now = clock.now();
      const { session, insert } = await prepareNewSession(db, user.id, "password", now);
      const extra = hooks.credentialsRevokedStatements?.({ db, userId: user.id, now, reason: "self_change" }) ?? [];
      // mcp_revoked_at rejects at /mcp the tokens authorized until now, including grants that revokeAllGrants
      // missed because the KV listing lags behind. Order matters: revoke existing sessions before inserting the
      // new one.
      await db.batch([
        db.update(users).set({ passwordHash, mcpRevokedAt: now, updatedAt: now }).where(eq(users.id, user.id)),
        revokeUserSessionsQuery(db, user.id, now),
        ...extra,
        insert,
      ]);
      await setCookiesForSession(names, c, session, config.jwtSecret, now);
      return c.body(null, 204);
    });
}
