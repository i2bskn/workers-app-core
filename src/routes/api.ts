import type { Context, Env, MiddlewareHandler } from "hono";
import type { User } from "../api-types.js";
import { apiError } from "../auth/middleware.js";
import { isJsonObject } from "../auth/validate.js";
import type { UserRow } from "../db/schema.js";

export function toApiUser(user: UserRow): User {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    created_at: user.createdAt,
    last_login_at: user.lastLoginAt,
  };
}

// Returns the JSON body if it is an object, otherwise null.
export async function readJsonObject<E extends Env>(c: Context<E>): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await c.req.json();
    return isJsonObject(body) ? body : null;
  } catch {
    return null;
  }
}

export type JsonCheck<Out, E extends Env = Env> = (
  body: Record<string, unknown>,
  c: Context<E>,
) => { ok: true; value: Out } | Response;

// Validates the JSON body and passes the result to c.req.valid("json").
// Reads the body regardless of Content-Type, and returns the error response from check as is.
export function jsonBody<In, Out extends object, E extends Env = any>(
  check: JsonCheck<Out, E>,
): MiddlewareHandler<E, string, { in: { json: In }; out: { json: Out } }> {
  return async (c, next) => {
    const body = await readJsonObject(c);
    if (!body) return apiError(c, 400, "invalid_body", "リクエストの形式が正しくありません");
    const result = check(body, c);
    if (result instanceof Response) return result;
    c.req.addValidatedData("json", result.value);
    return next();
  };
}
