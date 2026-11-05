// Helpers for the tests of an app built with createCore. Imports nothing from cloudflare:test, cloudflare:workers
// or the app: everything is passed in.
import { eq } from "drizzle-orm";
import { hashPassword } from "../auth/password.js";
import type { CoreBindings } from "../config.js";
import { createDb, type Db } from "../db/client.js";
import { users, type UserRow } from "../db/schema.js";

export const PASSWORD = "correct horse battery";

// A JWT_SECRET for the test configuration (at least 32 characters). Not a real secret.
export const TEST_JWT_SECRET = "test-secret-test-secret-test-secret-0123";

// The most values that D1 accepts in one statement.
export const D1_MAX_BOUND_VALUES = 100;

export type TestWorker<TestEnv> = {
  fetch(request: Request, env: TestEnv, ctx: ExecutionContext): Response | Promise<Response>;
};

export type TestHelpersOptions<TestEnv extends CoreBindings, Id extends string> = {
  worker: TestWorker<TestEnv>;
  env: TestEnv;
  createExecutionContext: () => ExecutionContext;
  // Accepted for symmetry with cloudflare:test; send() does not wait for waitUntil.
  waitOnExecutionContext?: (ctx: ExecutionContext) => Promise<void>;
  brandId: Id;
  // The origin of relative URLs.
  origin: string;
};

export type RequestOptions<TestEnv> = {
  method?: string;
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
  form?: Record<string, string>;
  json?: unknown;
  // Sent as is, without a Content-Type.
  body?: BodyInit;
  env?: Partial<TestEnv>;
  // Passed to the Worker as is, without the per-request copy. Overrides env.
  sharedEnv?: TestEnv;
  // Origin header for non-GET requests. Defaults to the request origin; null omits it.
  origin?: string | null;
};

export type SetCookie = { value: string; maxAge: number | null; raw: string };

export type SessionCookies<Id extends string> = Record<`__Host-${Id}_at` | `__Host-${Id}_rt`, string>;

export type LargeBind = { sql: string; count: number };

export type CreateUserParams = {
  email: string;
  role?: "admin" | "member";
  password?: string | null;
  createdAt?: number;
  // Run in the same batch as the INSERT, like the app's userCreatedStatements hook.
  userCreatedStatements?: (d1: D1Database, userId: string, now: number) => D1PreparedStatement[];
};

export function setCookies(res: Response): Record<string, SetCookie> {
  const result: Record<string, SetCookie> = {};
  for (const raw of res.headers.getSetCookie()) {
    const [pair = "", ...attributes] = raw.split(";").map((s) => s.trim());
    const index = pair.indexOf("=");
    const maxAge = attributes.find((a) => a.toLowerCase().startsWith("max-age="));
    result[pair.slice(0, index)] = {
      value: pair.slice(index + 1),
      maxAge: maxAge ? Number(maxAge.split("=")[1]) : null,
      raw,
    };
  }
  return result;
}

export function createTestHelpers<TestEnv extends CoreBindings, Id extends string>(
  options: TestHelpersOptions<TestEnv, Id>,
) {
  const { worker, env, createExecutionContext, brandId, origin: baseOrigin } = options;
  const accessCookie = `__Host-${brandId}_at` as const;
  const refreshCookie = `__Host-${brandId}_rt` as const;
  const db = createDb(env.DB);

  async function send(url: string, requestOptions: RequestOptions<TestEnv> = {}): Promise<Response> {
    const fullUrl = new URL(url, baseOrigin);
    const method =
      requestOptions.method ??
      (requestOptions.form || requestOptions.json !== undefined || requestOptions.body !== undefined ? "POST" : "GET");
    const headers = new Headers(requestOptions.headers);
    const origin = requestOptions.origin === undefined ? fullUrl.origin : requestOptions.origin;
    if (method !== "GET" && method !== "HEAD" && origin !== null) {
      headers.set("Origin", origin);
    }
    if (requestOptions.cookies) {
      headers.set(
        "Cookie",
        Object.entries(requestOptions.cookies)
          .map(([k, v]) => `${k}=${v}`)
          .join("; "),
      );
    }
    let body: BodyInit | undefined;
    if (requestOptions.form) {
      body = new URLSearchParams(requestOptions.form);
      headers.set("Content-Type", "application/x-www-form-urlencoded");
    } else if (requestOptions.json !== undefined) {
      body = typeof requestOptions.json === "string" ? requestOptions.json : JSON.stringify(requestOptions.json);
      headers.set("Content-Type", "application/json");
    } else if (requestOptions.body !== undefined) {
      body = requestOptions.body;
    }
    const request = new Request(fullUrl, { method, headers, body, redirect: "manual" });
    // Through the Worker entry point (OAuthProvider), like production.
    return worker.fetch(request, requestOptions.sharedEnv ?? { ...env, ...requestOptions.env }, createExecutionContext());
  }

  function sessionCookies(res: Response): SessionCookies<Id> {
    const cookies = setCookies(res);
    const at = cookies[accessCookie]?.value;
    const rt = cookies[refreshCookie]?.value;
    if (!at || !rt) throw new Error(`session cookies are missing: ${res.headers.getSetCookie().join(" | ")}`);
    return { [accessCookie]: at, [refreshCookie]: rt } as SessionCookies<Id>;
  }

  async function createUser(params: CreateUserParams): Promise<UserRow> {
    const now = params.createdAt ?? Date.now();
    const password = params.password === undefined ? PASSWORD : params.password;
    const passwordHash = password === null ? null : await hashPassword(password);
    const id = crypto.randomUUID();
    const role = params.role ?? "member";
    const extra = params.userCreatedStatements?.(env.DB, id, now) ?? [];
    if (extra.length === 0) {
      const [user] = await db
        .insert(users)
        .values({ id, email: params.email, role, passwordHash, createdAt: now, updatedAt: now })
        .returning();
      if (!user) throw new Error("failed to create user");
      return user;
    }
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO users (id, email, role, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
      ).bind(id, params.email, role, passwordHash, now, now),
      ...extra,
    ]);
    const user = await db.select().from(users).where(eq(users.id, id)).get();
    if (!user) throw new Error("failed to create user");
    return user;
  }

  async function login(email: string, password = PASSWORD): Promise<SessionCookies<Id>> {
    const res = await send("/auth/login", { form: { email, password, next: "/" } });
    if (res.status !== 303) throw new Error(`login failed: ${res.status}`);
    return sessionCookies(res);
  }

  // Deletes every row: first the app tables, in the order given (children first), then sessions and users.
  async function resetDb(appTables: string[] = []): Promise<void> {
    await env.DB.batch([
      ...appTables.map((table) => env.DB.prepare(`DELETE FROM ${table}`)),
      env.DB.prepare("DELETE FROM sessions"),
      env.DB.prepare("DELETE FROM users"),
    ]);
  }

  // A Db whose D1 binding runs before() once, right before the first statement matching pattern runs (alone
  // or in a batch), as if another request changed the data between the checks of a service and its write.
  function dbChangingBefore(pattern: RegExp, before: () => Promise<unknown>): Db {
    const real = env.DB;
    const wrapped = new WeakMap<object, D1PreparedStatement>();
    let done = false;
    async function runBefore() {
      if (done) return;
      done = true;
      await before();
    }
    const d1 = new Proxy(real, {
      get(target, prop) {
        if (prop === "prepare") {
          return (query: string) => {
            const statement = target.prepare(query);
            if (!pattern.test(query)) return statement;
            return {
              bind: (...values: unknown[]) => {
                const bound = statement.bind(...values);
                const wrapper = {
                  all: async () => (await runBefore(), bound.all()),
                  raw: async () => (await runBefore(), bound.raw()),
                  run: async () => (await runBefore(), bound.run()),
                  first: async () => (await runBefore(), bound.first()),
                };
                wrapped.set(wrapper, bound);
                return wrapper;
              },
            };
          };
        }
        if (prop === "batch") {
          return async (statements: object[]) => {
            if (statements.some((statement) => wrapped.has(statement))) await runBefore();
            return target.batch(
              statements.map((statement) => wrapped.get(statement) ?? (statement as D1PreparedStatement)),
            );
          };
        }
        const value: unknown = Reflect.get(target, prop, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    return createDb(d1);
  }

  async function countTable(table: string): Promise<number> {
    const row = await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{ count: number }>();
    return row?.count ?? 0;
  }

  // A D1 binding with some methods replaced, e.g. batch.
  function d1With(overrides: Partial<Record<keyof D1Database, unknown>>): D1Database {
    return new Proxy(env.DB, {
      get(target, prop) {
        if (prop in overrides) return overrides[prop as keyof D1Database];
        const value: unknown = Reflect.get(target, prop, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  }

  // A D1 binding that records the statements bound with more than D1_MAX_BOUND_VALUES values, which the local D1 may
  // accept but D1 does not. Nothing is thrown, since some callers swallow errors: the tests check that large is
  // empty. prepare returns the real statement with only bind replaced, and bind returns the real bound statement,
  // so that batch and the statements run without bind work as they are.
  function d1RecordingLargeBinds(): { d1: D1Database; large: LargeBind[] } {
    const large: LargeBind[] = [];
    const d1 = new Proxy(env.DB, {
      get(target, prop) {
        if (prop === "prepare") {
          return (query: string) => {
            const statement = target.prepare(query);
            return new Proxy(statement, {
              get(statementTarget, statementProp) {
                if (statementProp === "bind") {
                  return (...values: unknown[]) => {
                    if (values.length > D1_MAX_BOUND_VALUES) large.push({ sql: query, count: values.length });
                    return statementTarget.bind(...values);
                  };
                }
                const value: unknown = Reflect.get(statementTarget, statementProp, statementTarget);
                return typeof value === "function" ? value.bind(statementTarget) : value;
              },
            });
          };
        }
        const value: unknown = Reflect.get(target, prop, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    return { d1, large };
  }

  return {
    db,
    send,
    setCookies,
    sessionCookies,
    login,
    createUser,
    resetDb,
    dbChangingBefore,
    d1With,
    d1RecordingLargeBinds,
    countTable,
  };
}
