// Contract tests of the browser client against the routes of the fixture app: each function reaches the route
// that it means to call.
import { beforeEach, describe, expect, it } from "vitest";
import type { CoreBindings } from "../src/config.js";
import {
  changeUserRole,
  createUser as createUserWithClient,
  deleteUser,
  listUsers,
  reissueUserInvitation,
  resetUserMfa,
  resetUserPassword,
  revokeUserSessions,
  type ApiFetch,
} from "../src/client/index.js";
import type { UserRow } from "../src/db/schema.js";
import { OIDC_ORIGIN, createUser, login, oidcEnv, resetDb, send, type SessionCookies } from "./helpers.js";

// An ApiFetch that sends the request to the fixture app through send(), with the given session cookies.
function fixtureFetch(
  options: { cookies?: SessionCookies; env?: Partial<CoreBindings>; origin?: string } = {},
): ApiFetch {
  return async (input, init) => {
    if (typeof input !== "string") throw new Error("the client passes a string URL");
    return send(`${options.origin ?? ""}${input}`, {
      method: init?.method,
      headers: Object.fromEntries(new Headers(init?.headers)),
      body: init?.body ?? undefined,
      cookies: options.cookies,
      env: options.env as Partial<Cloudflare.Env> | undefined,
    });
  };
}

const MISSING_ID = "00000000-0000-4000-8000-000000000000";

let admin: UserRow;
let member: UserRow;
let adminFetch: ApiFetch;

beforeEach(async () => {
  await resetDb();
  admin = await createUser({ email: "admin@example.com", role: "admin" });
  member = await createUser({ email: "member@example.com" });
  adminFetch = fixtureFetch({ cookies: await login(admin.email) });
});

describe("user management client in password mode", () => {
  it("lists the users", async () => {
    const result = await listUsers(adminFetch);
    if (result.kind !== "ok") throw new Error(`unexpected result: ${JSON.stringify(result)}`);
    expect(result.authMode).toBe("password");
    expect(result.users.map((user) => user.email).sort()).toEqual([admin.email, member.email]);
  });

  it("creates a user with an invitation and issues a new one", async () => {
    const created = await createUserWithClient(adminFetch, { email: "invited@example.com", role: "member" });
    if (created.kind !== "ok") throw new Error(`unexpected result: ${JSON.stringify(created)}`);
    expect(created.user.email).toBe("invited@example.com");
    expect(created.user.status).toBe("invited");
    expect("invitation" in created.user).toBe(false);
    expect(created.invitation?.url).toEqual(expect.any(String));

    const reissued = await reissueUserInvitation(adminFetch, created.user.id);
    if (reissued.kind !== "ok") throw new Error(`unexpected result: ${JSON.stringify(reissued)}`);
    expect(reissued.invitation.url).not.toBe(created.invitation?.url);
    expect(reissued.invitation.expires_at).toEqual(expect.any(Number));
  });

  it("changes the role, resets the password and revokes the sessions of a user", async () => {
    expect(await changeUserRole(adminFetch, member.id, "admin")).toEqual({ kind: "ok" });
    expect(await resetUserPassword(adminFetch, member.id, "another password 123")).toEqual({ kind: "ok" });
    expect(await revokeUserSessions(adminFetch, member.id)).toEqual({ kind: "ok" });
  });

  it("returns the server's message when resetting the MFA of a user without MFA", async () => {
    expect(await resetUserMfa(adminFetch, member.id)).toEqual({
      kind: "error",
      message: "このユーザーは多要素認証を設定していません",
    });
  });

  it("deletes a user", async () => {
    expect(await deleteUser(adminFetch, member.id)).toEqual({ kind: "ok" });
    const result = await listUsers(adminFetch);
    if (result.kind !== "ok") throw new Error(`unexpected result: ${JSON.stringify(result)}`);
    expect(result.users.map((user) => user.id)).toEqual([admin.id]);
  });

  it("returns notFound for a missing user", async () => {
    expect(await changeUserRole(adminFetch, MISSING_ID, "admin")).toEqual({ kind: "notFound" });
    expect(await deleteUser(adminFetch, MISSING_ID)).toEqual({ kind: "notFound" });
  });
});

describe("user management client in oidc mode", () => {
  it("returns notFound for the password-only API, as for a missing user", async () => {
    // requireMode("password") runs before requireUser, so no session is needed.
    const oidcFetch = fixtureFetch({ env: oidcEnv, origin: OIDC_ORIGIN });
    expect(await resetUserPassword(oidcFetch, member.id, "another password 123")).toEqual({ kind: "notFound" });
  });
});
