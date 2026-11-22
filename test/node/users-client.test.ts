import { describe, expect, it, vi } from "vitest";
import {
  LoginRequiredError,
  RefreshFailedError,
  changeUserRole,
  createApiFetch,
  createUser,
  deleteUser,
  listUsers,
  reissueUserInvitation,
  resetUserMfa,
  resetUserPassword,
  revokeUserSessions,
  unexpectedResponseMessage,
  type ApiFetch,
  type User,
} from "../../src/client/index.js";

const USER_ID = "0b6f2d1e-3c4a-4b5d-8e9f-0a1b2c3d4e5f";
const USER: User = {
  id: USER_ID,
  email: "member@example.com",
  name: null,
  role: "member",
  created_at: 1,
  last_login_at: null,
  status: "invited",
};
const INVITATION = { url: "https://app.test/auth/invitation#token", expires_at: 2 };

type Reply = () => Response | Promise<Response>;

function json(body: unknown, status = 200): Reply {
  return () => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function empty(status: number): Reply {
  return () => new Response(null, { status });
}

function text(body: string, status = 200): Reply {
  return () => new Response(body, { status });
}

function apiError(status: number, code: string, message: string): Reply {
  return json({ error: { code, message } }, status);
}

function rejects(error: unknown): Reply {
  return () => Promise.reject(error);
}

// An ApiFetch that answers from a queue, in order.
function fakeFetch(...replies: Reply[]) {
  const queue = [...replies];
  return vi.fn<ApiFetch>(async (input) => {
    const reply = queue.shift();
    if (!reply) throw new Error(`unexpected fetch: ${String(input)}`);
    return reply();
  });
}

const JSON_HEADERS = { "Content-Type": "application/json" };

type Call = {
  name: string;
  run: (fetch: ApiFetch, userId?: string) => Promise<{ kind: string }>;
  url: string;
  init: RequestInit;
  // The ok reply of the server.
  ok: Reply;
};

const userCalls: Call[] = [
  {
    name: "changeUserRole",
    run: (fetch, id = USER_ID) => changeUserRole(fetch, id, "admin"),
    url: `/api/v1/users/${USER_ID}`,
    init: { method: "PATCH", headers: JSON_HEADERS, body: JSON.stringify({ role: "admin" }) },
    ok: json({ ...USER, role: "admin" }),
  },
  {
    name: "resetUserPassword",
    run: (fetch, id = USER_ID) => resetUserPassword(fetch, id, "new password 123"),
    url: `/api/v1/users/${USER_ID}/password`,
    init: { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ password: "new password 123" }) },
    ok: empty(204),
  },
  {
    name: "reissueUserInvitation",
    run: (fetch, id = USER_ID) => reissueUserInvitation(fetch, id),
    url: `/api/v1/users/${USER_ID}/invitation`,
    init: { method: "POST" },
    ok: json(INVITATION),
  },
  {
    name: "resetUserMfa",
    run: (fetch, id = USER_ID) => resetUserMfa(fetch, id),
    url: `/api/v1/users/${USER_ID}/reset-mfa`,
    init: { method: "POST" },
    ok: empty(204),
  },
  {
    name: "revokeUserSessions",
    run: (fetch, id = USER_ID) => revokeUserSessions(fetch, id),
    url: `/api/v1/users/${USER_ID}/revoke-sessions`,
    init: { method: "POST" },
    ok: empty(204),
  },
  {
    name: "deleteUser",
    run: (fetch, id = USER_ID) => deleteUser(fetch, id),
    url: `/api/v1/users/${USER_ID}`,
    init: { method: "DELETE" },
    ok: empty(204),
  },
];

const allCalls: Call[] = [
  {
    name: "listUsers",
    run: (fetch) => listUsers(fetch),
    url: "/api/v1/users",
    init: { method: "GET" },
    ok: json({ users: [USER], auth_mode: "password" }),
  },
  {
    name: "createUser",
    run: (fetch) => createUser(fetch, { email: USER.email, role: "member" }),
    url: "/api/v1/users",
    init: { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ email: USER.email, role: "member" }) },
    ok: json({ ...USER, invitation: INVITATION }, 201),
  },
  ...userCalls,
];

describe.each(allCalls)("$name", ({ run, url, init, ok }) => {
  it("calls fetch with the method, URL, headers and body", async () => {
    const fetch = fakeFetch(ok);
    expect((await run(fetch)).kind).toBe("ok");
    expect(fetch.mock.calls).toEqual([[url, init]]);
  });

  it("passes only the method when there is no body", async () => {
    const fetch = fakeFetch(ok);
    await run(fetch);
    const sent = fetch.mock.calls[0]?.[1];
    if (init.body === undefined) {
      expect(Object.keys(sent ?? {})).toEqual(["method"]);
    } else {
      expect(typeof sent?.body).toBe("string");
    }
  });

  it("returns the server's message for 409", async () => {
    const fetch = fakeFetch(apiError(409, "conflict", "競合しました"));
    expect(await run(fetch)).toEqual({ kind: "error", message: "競合しました" });
  });

  it("returns the server's message for 401 from a plain fetch", async () => {
    const fetch = fakeFetch(apiError(401, "unauthorized", "ログインしてください"));
    expect(await run(fetch)).toEqual({ kind: "error", message: "ログインしてください" });
  });

  it("returns an unexpected response message for a 500 that is not JSON", async () => {
    const fetch = fakeFetch(text("oops", 500));
    expect(await run(fetch)).toEqual({ kind: "error", message: unexpectedResponseMessage(500) });
  });

  it("returns redirecting when fetch rejects with LoginRequiredError", async () => {
    const fetch = fakeFetch(rejects(new LoginRequiredError()));
    expect(await run(fetch)).toEqual({ kind: "redirecting" });
  });

  it.each([new TypeError("Failed to fetch"), new RefreshFailedError(503)])(
    "returns unknown when fetch rejects with %s",
    async (error) => {
      const fetch = fakeFetch(rejects(error));
      expect(await run(fetch)).toEqual({ kind: "unknown" });
    },
  );
});

describe.each(userCalls)("$name with a user ID", ({ run }) => {
  it("returns notFound for 404", async () => {
    const fetch = fakeFetch(apiError(404, "not_found", "ユーザーが見つかりません"));
    expect(await run(fetch)).toEqual({ kind: "notFound" });
  });

  it.each(["", "..", "a/b", "a".repeat(65)])("does not send an invalid user ID %j", async (id) => {
    const fetch = fakeFetch();
    expect(await run(fetch, id)).toEqual({ kind: "error", message: "ユーザーが見つかりません" });
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("listUsers", () => {
  it("returns the users and the auth mode", async () => {
    const fetch = fakeFetch(json({ users: [USER], auth_mode: "oidc" }));
    expect(await listUsers(fetch)).toEqual({ kind: "ok", users: [USER], authMode: "oidc" });
  });

  it("accepts an auth mode that the client does not know", async () => {
    const fetch = fakeFetch(json({ users: [], auth_mode: "saml" }));
    expect(await listUsers(fetch)).toEqual({ kind: "ok", users: [], authMode: "saml" });
  });

  it("returns an error with the server's message for 404", async () => {
    const fetch = fakeFetch(apiError(404, "not_found", "見つかりません"));
    expect(await listUsers(fetch)).toEqual({ kind: "error", message: "見つかりません" });
  });

  it.each([
    ["null", json(null)],
    ["an empty object", json({})],
    ["users that is not an array", json({ users: {}, auth_mode: "password" })],
    ["a numeric auth_mode", json({ users: [], auth_mode: 1 })],
    ["a body that is not JSON", text("<html>")],
  ])("returns an error for %s", async (_, reply) => {
    const fetch = fakeFetch(reply);
    await expect(listUsers(fetch)).resolves.toEqual({ kind: "error", message: unexpectedResponseMessage(200) });
  });
});

describe("createUser", () => {
  const input = { email: USER.email, role: "member" as const };

  it.each([
    ["an invitation", { ...USER, invitation: INVITATION }, INVITATION],
    ["a null invitation", { ...USER, invitation: null }, null],
    ["no invitation", { ...USER }, null],
  ])("separates %s from the user", async (_, body, invitation) => {
    const fetch = fakeFetch(json(body, 201));
    const result = await createUser(fetch, input);
    expect(result).toEqual({ kind: "ok", user: USER, invitation });
    if (result.kind !== "ok") throw new Error("not ok");
    expect("invitation" in result.user).toBe(false);
  });

  it("returns an error with the server's message for 404", async () => {
    const fetch = fakeFetch(apiError(404, "not_found", "見つかりません"));
    expect(await createUser(fetch, input)).toEqual({ kind: "error", message: "見つかりません" });
  });

  it.each([
    ["null", json(null, 201)],
    ["an array", json([], 201)],
    ["a body that is not JSON", text("created", 201)],
  ])("returns an error for %s", async (_, reply) => {
    const fetch = fakeFetch(reply);
    await expect(createUser(fetch, input)).resolves.toEqual({ kind: "error", message: unexpectedResponseMessage(201) });
  });
});

describe("reissueUserInvitation", () => {
  it("returns the invitation", async () => {
    const fetch = fakeFetch(json(INVITATION));
    expect(await reissueUserInvitation(fetch, USER_ID)).toEqual({ kind: "ok", invitation: INVITATION });
  });

  it.each([
    ["an empty object", json({})],
    ["a body that is not JSON", text("ok")],
  ])("returns an error for %s", async (_, reply) => {
    const fetch = fakeFetch(reply);
    await expect(reissueUserInvitation(fetch, USER_ID)).resolves.toEqual({
      kind: "error",
      message: unexpectedResponseMessage(200),
    });
  });
});

describe("changeUserRole", () => {
  it("does not read the updated user", async () => {
    const fetch = fakeFetch(text("not json"));
    expect(await changeUserRole(fetch, USER_ID, "admin")).toEqual({ kind: "ok" });
  });
});

describe("with createApiFetch", () => {
  it("sends the same body string again after refreshing on 401", async () => {
    const replies = [empty(401), empty(204)];
    const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
      if (input === "/auth/refresh") return new Response(null, { status: 204 });
      const reply = replies.shift();
      if (!reply) throw new Error(`unexpected fetch: ${String(input)}`);
      return reply();
    });
    const apiFetch = createApiFetch({ fetch, redirectToLogin: vi.fn(), currentPath: () => "/" });
    expect(await resetUserPassword(apiFetch, USER_ID, "new password 123")).toEqual({ kind: "ok" });
    const [first, refresh, retry] = fetch.mock.calls;
    expect(refresh?.[0]).toBe("/auth/refresh");
    expect(retry?.[0]).toBe(`/api/v1/users/${USER_ID}/password`);
    expect(retry?.[1]?.body).toBe(JSON.stringify({ password: "new password 123" }));
    expect(retry?.[1]?.body).toBe(first?.[1]?.body);
  });
});
