import { env } from "cloudflare:workers";
import { sql } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createInitialAdmin, deleteUser } from "../src/auth/users.js";
import type { UserRow } from "../src/db/schema.js";
import type { CoreHooks } from "../src/hooks.js";
import { hooks, userNotes, type FixtureBindings } from "./fixture/src/index.js";
import {
  AT,
  countNotes,
  createUser,
  db,
  dbChangingBefore,
  login,
  PASSWORD,
  resetDb,
  RT,
  send,
  sessionCookies,
  setCookies,
} from "./helpers.js";

type Hooks = CoreHooks<FixtureBindings, unknown>;

const NEW_PASSWORD = "another long passphrase";

// Inserts a note for the new user, guarded by the existence of the user as the contract requires.
const noteOnCreate: NonNullable<Hooks["userCreatedStatements"]> = (d1, userId) => [
  d1
    .prepare("INSERT INTO user_notes (user_id, note) SELECT ?1, 'created' WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)")
    .bind(userId),
];

// A statement that always fails (NOT NULL), to show that the hook runs in the same batch as the INSERT.
const failingOnCreate: NonNullable<Hooks["userCreatedStatements"]> = (d1, userId) => [
  d1.prepare("INSERT INTO user_notes (user_id, note) VALUES (?, NULL)").bind(userId),
];

async function userCount(): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS count FROM users").first<{ count: number }>();
  return row?.count ?? 0;
}

async function notes(userId: string): Promise<string[]> {
  const { results } = await env.DB.prepare("SELECT note FROM user_notes WHERE user_id = ? ORDER BY id")
    .bind(userId)
    .all<{ note: string }>();
  return results.map((row) => row.note);
}

beforeEach(resetDb);

afterEach(() => {
  vi.restoreAllMocks();
});

const setupForm = { email: "admin@example.com", name: "Admin", password: PASSWORD, password_confirm: PASSWORD };

describe("userCreatedStatements", () => {
  it("runs with the setup INSERT", async () => {
    hooks.userCreatedStatements = noteOnCreate;
    expect((await send("/auth/setup", { form: setupForm })).status).toBe(303);
    const [admin] = await db.select().from(userNotes).all();
    expect(admin?.note).toBe("created");
    expect(await countNotes()).toBe(1);
  });

  it("rolls back the setup INSERT when a statement fails", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    hooks.userCreatedStatements = failingOnCreate;
    expect((await send("/auth/setup", { form: setupForm })).status).toBe(500);
    expect(await userCount()).toBe(0);
  });

  it("inserts nothing when the setup INSERT inserts nothing", async () => {
    await createUser({ email: "first@example.com", role: "admin" });
    const created = await createInitialAdmin(
      db,
      { email: "second@example.com", name: null, passwordHash: "x", now: Date.now() },
      noteOnCreate,
    );
    expect(created).toBeNull();
    expect(await countNotes()).toBe(0);
  });

  it("runs with POST /api/v1/users", async () => {
    const admin = await createUser({ email: "admin@example.com", role: "admin" });
    const cookies = await login(admin.email);
    hooks.userCreatedStatements = noteOnCreate;
    const res = await send("/api/v1/users", {
      cookies,
      json: { email: "new@example.com", password: NEW_PASSWORD, role: "member" },
    });
    expect(res.status).toBe(201);
    const { id } = (await res.json()) as { id: string };
    expect(await notes(id)).toEqual(["created"]);
  });

  it("rolls back POST /api/v1/users when a statement fails, and keeps email_taken", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const admin = await createUser({ email: "admin@example.com", role: "admin" });
    const cookies = await login(admin.email);
    hooks.userCreatedStatements = failingOnCreate;
    const failed = await send("/api/v1/users", {
      cookies,
      json: { email: "new@example.com", password: NEW_PASSWORD, role: "member" },
    });
    expect(failed.status).toBe(500);
    expect(await userCount()).toBe(1);

    hooks.userCreatedStatements = noteOnCreate;
    const taken = await send("/api/v1/users", {
      cookies,
      json: { email: "admin@example.com", password: NEW_PASSWORD, role: "member" },
    });
    expect(taken.status).toBe(409);
    expect(((await taken.json()) as { error: { code: string } }).error.code).toBe("email_taken");
    expect(await countNotes()).toBe(0);
  });

  it("answers 500, not email_taken, when a statement of the hook violates a UNIQUE constraint", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const admin = await createUser({ email: "admin@example.com", role: "admin" });
    const cookies = await login(admin.email);
    // Two rows with the same primary key: "UNIQUE constraint failed: user_notes.id".
    hooks.userCreatedStatements = (d1, userId) => [
      d1.prepare("INSERT INTO user_notes (id, user_id, note) VALUES (1, ?, 'a')").bind(userId),
      d1.prepare("INSERT INTO user_notes (id, user_id, note) VALUES (1, ?, 'b')").bind(userId),
    ];
    const res = await send("/api/v1/users", {
      cookies,
      json: { email: "new@example.com", password: NEW_PASSWORD, role: "member" },
    });
    expect(res.status).toBe(500);
    expect(await userCount()).toBe(1);
  });

  it("is run by the createUser test helper only when passed to it", async () => {
    const user = await createUser({ email: "a@example.com", userCreatedStatements: noteOnCreate });
    expect(await notes(user.id)).toEqual(["created"]);
    hooks.userCreatedStatements = noteOnCreate;
    const other = await createUser({ email: "b@example.com" });
    expect(await notes(other.id)).toEqual([]);
  });
});

describe("beforeSessionIssued", () => {
  let alice: UserRow;
  let calls: { userId: string; now: number }[];

  beforeEach(async () => {
    alice = await createUser({ email: "alice@example.com", role: "admin" });
    calls = [];
    hooks.beforeSessionIssued = async ({ env: hookEnv, db: hookDb, userId, now }) => {
      expect(hookEnv.DB).toBeDefined();
      expect(hookDb.$client).toBeDefined();
      calls.push({ userId, now });
    };
  });

  it("is called on password login", async () => {
    await login(alice.email);
    expect(calls).toEqual([{ userId: alice.id, now: expect.any(Number) }]);
  });

  it("is not called for a wrong password", async () => {
    const res = await send("/auth/login", { form: { email: alice.email, password: "wrong password!" } });
    expect(res.status).toBe(401);
    expect(calls).toEqual([]);
  });

  it("is called on POST /auth/refresh", async () => {
    const cookies = await login(alice.email);
    calls = [];
    expect((await send("/auth/refresh", { method: "POST", cookies })).status).toBe(204);
    expect(calls).toEqual([{ userId: alice.id, now: expect.any(Number) }]);
  });

  it("is called on GET /auth/login with a valid refresh cookie", async () => {
    const cookies = await login(alice.email);
    calls = [];
    const res = await send("/auth/login?next=/x", { cookies: { [RT]: cookies[RT] } });
    expect(res.status).toBe(302);
    sessionCookies(res);
    expect(calls).toEqual([{ userId: alice.id, now: expect.any(Number) }]);
  });

  it("is not called on the setup", async () => {
    await resetDb();
    hooks.beforeSessionIssued = async ({ userId, now }) => {
      calls.push({ userId, now });
    };
    expect((await send("/auth/setup", { form: setupForm })).status).toBe(303);
    expect(calls).toEqual([]);
  });

  it("fails password login with 500 and sets no cookies when it throws", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    hooks.beforeSessionIssued = async () => {
      throw new Error("hook failed");
    };
    const res = await send("/auth/login", { form: { email: alice.email, password: PASSWORD, next: "/" } });
    expect(res.status).toBe(500);
    expect(await res.text()).toContain("サーバーでエラーが発生しました");
    expect(res.headers.getSetCookie()).toEqual([]);
    const row = await env.DB.prepare("SELECT COUNT(*) AS count FROM sessions").first<{ count: number }>();
    expect(row?.count).toBe(0);
  });

  it("fails POST /auth/refresh with a 500 JSON error and sets no cookies when it throws", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const cookies = await login(alice.email);
    hooks.beforeSessionIssued = async () => {
      throw new Error("hook failed");
    };
    const res = await send("/auth/refresh", { method: "POST", cookies });
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: { code: "internal_error", message: expect.any(String) } });
    expect(Object.keys(setCookies(res))).toEqual([]);
  });

  it("fails GET /auth/login with 500 and sets no cookies when it throws", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const cookies = await login(alice.email);
    hooks.beforeSessionIssued = async () => {
      throw new Error("hook failed");
    };
    const res = await send("/auth/login?next=/x", { cookies: { [AT]: cookies[AT], [RT]: cookies[RT] } });
    expect(res.status).toBe(500);
    expect(res.headers.getSetCookie()).toEqual([]);
  });

  it("is not called when GET /auth/login loses a concurrent rotation", async () => {
    const cookies = await login(alice.email);
    expect((await send("/auth/refresh", { method: "POST", cookies })).status).toBe(204);
    calls = [];
    // The same refresh token again, within the reuse grace period.
    const res = await send("/auth/login?next=/x", { cookies: { [RT]: cookies[RT] } });
    expect(res.status).toBe(302);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(calls).toEqual([]);
  });
});

describe("userDeleteStatements", () => {
  let admin: UserRow;
  let member: UserRow;

  beforeEach(async () => {
    admin = await createUser({ email: "admin@example.com", role: "admin" });
    member = await createUser({ email: "member@example.com" });
    for (const user of [admin, member]) {
      await env.DB.prepare("INSERT INTO user_notes (user_id, note) VALUES (?1, 'a'), (?1, 'b')").bind(user.id).run();
    }
  });

  const deleteNotes: NonNullable<Hooks["userDeleteStatements"]> = async ({ d1, userId, guard }) => ({
    statements: [
      d1.prepare(`SELECT COUNT(*) AS count FROM user_notes WHERE user_id = ?1 AND ${guard}`).bind(userId),
      d1.prepare(`DELETE FROM user_notes WHERE user_id = ?1 AND ${guard} RETURNING note`).bind(userId),
    ],
    read: (results) => ({ length: results.length, deleted: results[1]?.results }),
  });

  it("runs the statements in the delete batch and returns what read returns", async () => {
    expect(await deleteUser(db, member.id, deleteNotes)).toEqual({
      ok: true,
      data: { length: 2, deleted: [{ note: "a" }, { note: "b" }] },
    });
    expect(await countNotes(member.id)).toBe(0);
    expect(await countNotes(admin.id)).toBe(2);
  });

  it("keeps the rows when the last-admin guard refuses in the batch", async () => {
    const target = await createUser({ email: "target@example.com", role: "admin" });
    await env.DB.prepare("INSERT INTO user_notes (user_id, note) VALUES (?, 'x')").bind(target.id).run();
    // Demotes the other admin right before the first statement of the batch (the app's).
    const raced = dbChangingBefore(/^SELECT COUNT\(\*\) AS count FROM user_notes/i, () =>
      env.DB.prepare("UPDATE users SET role = 'member' WHERE id = ?").bind(admin.id).run(),
    );
    expect(await deleteUser(raced, target.id, deleteNotes)).toEqual({ ok: false, error: "last_admin" });
    expect(await countNotes(target.id)).toBe(1);
  });

  it("is not called when the fast path refuses", async () => {
    const hook = vi.fn(deleteNotes);
    expect(await deleteUser(db, admin.id, hook)).toEqual({ ok: false, error: "last_admin" });
    expect(await deleteUser(db, crypto.randomUUID(), hook)).toEqual({ ok: false, error: "not_found" });
    expect(hook).not.toHaveBeenCalled();
  });

  it("runs through DELETE /api/v1/users/:id and passes the data to afterUserDeleted", async () => {
    const cookies = await login(admin.email);
    const after = vi.fn<NonNullable<Hooks["afterUserDeleted"]>>(async () => {});
    hooks.userDeleteStatements = deleteNotes;
    hooks.afterUserDeleted = after;
    expect((await send(`/api/v1/users/${member.id}`, { method: "DELETE", cookies })).status).toBe(204);
    expect(await countNotes(member.id)).toBe(0);
    expect(after).toHaveBeenCalledWith({
      env: expect.anything(),
      userId: member.id,
      data: { length: 2, deleted: [{ note: "a" }, { note: "b" }] },
    });
  });

  it("returns 204 when afterUserDeleted throws, and logs it", async () => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    const cookies = await login(admin.email);
    hooks.afterUserDeleted = async () => {
      throw new Error("r2 is down");
    };
    expect((await send(`/api/v1/users/${member.id}`, { method: "DELETE", cookies })).status).toBe(204);
    expect(errorLog).toHaveBeenCalledWith("after user delete hook failed", expect.objectContaining({ userId: member.id }));
  });
});

describe("credentialsRevokedStatements", () => {
  let admin: UserRow;
  let member: UserRow;
  let reasons: string[];

  beforeEach(async () => {
    admin = await createUser({ email: "admin@example.com", role: "admin" });
    member = await createUser({ email: "member@example.com" });
    reasons = [];
  });

  // Records the reason with the number of active sessions of the user when the statement runs.
  const recordActiveSessions: NonNullable<Hooks["credentialsRevokedStatements"]> = ({ db: hookDb, userId, reason }) => {
    reasons.push(reason);
    return [
      hookDb.insert(userNotes).select(sql`
        SELECT NULL, ${userId}, ${reason} || ':' || (SELECT COUNT(*) FROM sessions WHERE user_id = ${userId} AND revoked_at IS NULL)`),
    ];
  };

  // Fails (NOT NULL), so that the whole batch is rolled back.
  const failing: NonNullable<Hooks["credentialsRevokedStatements"]> = ({ db: hookDb, userId }) => [
    hookDb.insert(userNotes).values({ userId, note: sql`NULL` }),
  ];

  async function mcpRevokedAt(userId: string): Promise<number | null> {
    const row = await env.DB.prepare("SELECT mcp_revoked_at FROM users WHERE id = ?").bind(userId).first<{
      mcp_revoked_at: number | null;
    }>();
    return row?.mcp_revoked_at ?? null;
  }

  it("runs after the session revocation and before the new session on a password change", async () => {
    const cookies = await login(member.email);
    hooks.credentialsRevokedStatements = recordActiveSessions;
    const res = await send("/api/v1/me/password", {
      cookies,
      json: { current_password: PASSWORD, new_password: NEW_PASSWORD },
    });
    expect(res.status).toBe(204);
    expect(reasons).toEqual(["self_change"]);
    expect(await notes(member.id)).toEqual(["self_change:0"]);
  });

  it("runs after the session revocation on an admin password reset", async () => {
    await login(member.email);
    const cookies = await login(admin.email);
    hooks.credentialsRevokedStatements = recordActiveSessions;
    const res = await send(`/api/v1/users/${member.id}/password`, { cookies, json: { password: NEW_PASSWORD } });
    expect(res.status).toBe(204);
    expect(reasons).toEqual(["admin_reset"]);
    expect(await notes(member.id)).toEqual(["admin_reset:0"]);
  });

  it("runs after the session revocation on revoke-sessions", async () => {
    await login(member.email);
    const cookies = await login(admin.email);
    hooks.credentialsRevokedStatements = recordActiveSessions;
    const res = await send(`/api/v1/users/${member.id}/revoke-sessions`, { method: "POST", cookies });
    expect(res.status).toBe(204);
    expect(reasons).toEqual(["revoke_sessions"]);
    expect(await notes(member.id)).toEqual(["revoke_sessions:0"]);
  });

  it.each([
    ["self_change", "/api/v1/me/password", { current_password: PASSWORD, new_password: NEW_PASSWORD }, "member"],
    ["admin_reset", "/api/v1/users/:id/password", { password: NEW_PASSWORD }, "admin"],
    ["revoke_sessions", "/api/v1/users/:id/revoke-sessions", undefined, "admin"],
  ] as const)("rolls back the batch of %s when a statement fails", async (_reason, path, json, as) => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const memberCookies = await login(member.email);
    const cookies = as === "member" ? memberCookies : await login(admin.email);
    hooks.credentialsRevokedStatements = failing;
    const res = await send(path.replace(":id", member.id), { method: "POST", cookies, json });
    expect(res.status).toBe(500);
    expect(await mcpRevokedAt(member.id)).toBeNull();
    // The sessions are not revoked either.
    expect((await send("/api/v1/me", { cookies: memberCookies })).status).toBe(200);
  });
});
