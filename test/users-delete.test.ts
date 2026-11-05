import { env } from "cloudflare:workers";
import { eq } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deleteUser } from "../src/auth/users.js";
import { users, type UserRow } from "../src/db/schema.js";
import { createUser, db, dbChangingBefore, login, resetDb, send, type SessionCookies } from "./helpers.js";

const T0 = Date.UTC(2026, 9, 1);

async function countSessions(userId: string): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?")
    .bind(userId)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

function readUser(id: string) {
  return db.select().from(users).where(eq(users.id, id)).get();
}

function deleteRequest(id: string, cookies?: SessionCookies): Promise<Response> {
  return send(`/api/v1/users/${id}`, { method: "DELETE", cookies });
}

async function errorCode(res: Response): Promise<string> {
  return ((await res.json()) as { error: { code: string } }).error.code;
}

let admin: UserRow;
let member: UserRow;
let adminCookies: SessionCookies;
let memberCookies: SessionCookies;

beforeEach(async () => {
  await resetDb();
  admin = await createUser({ email: "admin@example.com", role: "admin", createdAt: T0 });
  member = await createUser({ email: "member@example.com", role: "member", createdAt: T0 });
  adminCookies = await login(admin.email);
  memberCookies = await login(member.email);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("DELETE /api/v1/users/:id", () => {
  it("deletes the user with their sessions", async () => {
    await login(member.email);
    expect(await countSessions(member.id)).toBe(2);

    const res = await deleteRequest(member.id, adminCookies);
    expect(res.status).toBe(204);

    expect(await readUser(member.id)).toBeUndefined();
    expect(await countSessions(member.id)).toBe(0);
  });

  it("leaves other users and their sessions alone", async () => {
    const other = await createUser({ email: "other@example.com", createdAt: T0 });
    await login(other.email);

    expect((await deleteRequest(member.id, adminCookies)).status).toBe(204);

    expect(await readUser(other.id)).toBeDefined();
    expect(await countSessions(other.id)).toBe(1);
    expect(await countSessions(admin.id)).toBe(1);
  });

  it("signs the deleted user out", async () => {
    expect((await send("/api/v1/me", { cookies: memberCookies })).status).toBe(200);
    expect((await deleteRequest(member.id, adminCookies)).status).toBe(204);
    expect((await send("/api/v1/me", { cookies: memberCookies })).status).toBe(401);
  });

  it("rejects the requester themselves, an unknown user, members and anonymous requests", async () => {
    const self = await deleteRequest(admin.id, adminCookies);
    expect(self.status).toBe(400);
    expect(await errorCode(self)).toBe("cannot_delete_self");

    const unknown = await deleteRequest(crypto.randomUUID(), adminCookies);
    expect(unknown.status).toBe(404);
    expect(await errorCode(unknown)).toBe("not_found");

    const byMember = await deleteRequest(admin.id, memberCookies);
    expect(byMember.status).toBe(403);
    expect(await errorCode(byMember)).toBe("forbidden");

    expect((await deleteRequest(member.id)).status).toBe(401);

    expect(await readUser(admin.id)).toBeDefined();
    expect(await readUser(member.id)).toBeDefined();
  });

  it("lets an admin delete another admin when there are two", async () => {
    const second = await createUser({ email: "second@example.com", role: "admin", createdAt: T0 });
    expect((await deleteRequest(second.id, adminCookies)).status).toBe(204);
    expect(await readUser(second.id)).toBeUndefined();
  });
});

describe("deleteUser", () => {
  it("returns ok and deletes the user with their sessions", async () => {
    expect(await deleteUser(db, member.id)).toEqual({ ok: true });
    expect(await readUser(member.id)).toBeUndefined();
    expect(await countSessions(member.id)).toBe(0);
  });

  it("refuses to delete the last admin and deletes nothing", async () => {
    expect(await deleteUser(db, admin.id)).toEqual({ ok: false, error: "last_admin" });
    expect(await readUser(admin.id)).toMatchObject({ role: "admin" });
    expect(await countSessions(admin.id)).toBe(1);
  });

  it("returns not_found for an unknown user", async () => {
    expect(await deleteUser(db, crypto.randomUUID())).toEqual({ ok: false, error: "not_found" });
  });
});

describe("deleteUser under a race", () => {
  it("deletes nothing when the requester stops being an admin after the check", async () => {
    const target = await createUser({ email: "target@example.com", role: "admin", createdAt: T0 });
    await login(target.email);
    // The first statement of the batch.
    const raced = dbChangingBefore(/^DELETE FROM sessions/i, () =>
      env.DB.prepare("UPDATE users SET role = 'member' WHERE id = ?").bind(admin.id).run(),
    );

    expect(await deleteUser(raced, target.id)).toEqual({ ok: false, error: "last_admin" });

    expect(await readUser(target.id)).toMatchObject({ role: "admin" });
    expect(await countSessions(target.id)).toBe(1);
  });

  it("deletes nothing when the user is deleted after the check", async () => {
    const raced = dbChangingBefore(/^DELETE FROM sessions/i, () =>
      env.DB.batch([
        env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(member.id),
        env.DB.prepare("DELETE FROM users WHERE id = ?").bind(member.id),
      ]),
    );

    expect(await deleteUser(raced, member.id)).toEqual({ ok: false, error: "not_found" });
    expect(await readUser(member.id)).toBeUndefined();
  });
});
