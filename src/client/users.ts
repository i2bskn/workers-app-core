// Browser-safe: imports no server module. Types only from the API types.
//
// Functions for the user management API (/api/v1/users). Each takes the ApiFetch made by createApiFetch: pass the
// same instance that the app gives to hc(), so that concurrent 401s share one refresh and the move to the login page
// happens once. The redirecting outcome relies on `instanceof LoginRequiredError` of this package, so the fetch must
// come from this package's createApiFetch.
//
// The values imported from ./index.js are used only inside the function bodies: index.js re-exports this module,
// so they are not initialized yet while this module is evaluated.
import type { CreateUserRequest, CreateUserResponse, Invitation, User, UserList } from "../api-types.js";
import { LoginRequiredError, responseErrorMessage, unexpectedResponseMessage, type ApiFetch } from "./index.js";

// The failures shared by every function below. None of them rejects.
export type UserApiFailure =
  // An error response (4xx and 5xx; 404 too for listUsers and createUser), or an ok response whose body is not JSON
  // or not in the expected shape. message is the server's message when it has one.
  | { kind: "error"; message: string }
  // The request did not get a response (the fetch rejected with something other than LoginRequiredError), so it may
  // have succeeded on the server. For listUsers, a GET, this only means that the server could not be reached.
  | { kind: "unknown" }
  // Login is required and the move to the login page has started.
  | { kind: "redirecting" };

export type ListUsersResult = { kind: "ok"; users: User[]; authMode: UserList["auth_mode"] } | UserApiFailure;

// invitation is the link for the user to set their password, returned only once: set when a user is created without
// a password in password mode, null otherwise.
export type CreateUserResult = { kind: "ok"; user: User; invitation: Invitation | null } | UserApiFailure;

// The outcome of the actions on a user. notFound means the user is gone.
export type UserActionResult = { kind: "ok" } | { kind: "notFound" } | UserApiFailure;

export type InvitationResult = { kind: "ok"; invitation: Invitation } | { kind: "notFound" } | UserApiFailure;

const USERS_PATH = "/api/v1/users";

// Matches the user IDs of the core (crypto.randomUUID()). Other values are not sent, so that `..` or `/` cannot
// change the path.
const USER_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

const INVALID_USER_ID = { kind: "error", message: "ユーザーが見つかりません" } as const;

function userPath(userId: string, suffix = ""): string {
  return `${USERS_PATH}/${encodeURIComponent(userId)}${suffix}`;
}

// A request with a JSON body. The body is a string so that createApiFetch can send the same init again after 401.
function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

// Calls fetch. A rejection becomes the failure to return; never rejects.
async function send(
  fetch: ApiFetch,
  path: string,
  init: RequestInit,
): Promise<{ kind: "response"; res: Response } | Exclude<UserApiFailure, { kind: "error" }>> {
  try {
    return { kind: "response", res: await fetch(path, init) };
  } catch (error) {
    if (error instanceof LoginRequiredError) return { kind: "redirecting" };
    return { kind: "unknown" };
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Reads the JSON body of an ok response; null if it is not JSON or not an object.
async function okObject(res: Response): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await res.json();
    return isObject(body) ? body : null;
  } catch {
    return null;
  }
}

function unexpected(res: Response): UserApiFailure {
  return { kind: "error", message: unexpectedResponseMessage(res.status) };
}

// The outcome of an action that does not read the ok body. 404 is notFound; other errors are shown with the
// server's message.
async function userAction(fetch: ApiFetch, path: string, init: RequestInit): Promise<UserActionResult> {
  const sent = await send(fetch, path, init);
  if (sent.kind !== "response") return sent;
  const { res } = sent;
  if (res.ok) return { kind: "ok" };
  if (res.status === 404) return { kind: "notFound" };
  return { kind: "error", message: await responseErrorMessage(res) };
}

// Lists the users and the auth mode. Admins only. 404 is an error too: the list itself is never missing.
// Never rejects.
export async function listUsers(fetch: ApiFetch): Promise<ListUsersResult> {
  const sent = await send(fetch, USERS_PATH, { method: "GET" });
  if (sent.kind !== "response") return sent;
  const { res } = sent;
  if (!res.ok) return { kind: "error", message: await responseErrorMessage(res) };
  const body = await okObject(res);
  // The items are not checked, and auth_mode is not compared with the known modes, so that a new mode on the
  // server does not break the list.
  if (body === null || !Array.isArray(body.users) || typeof body.auth_mode !== "string") return unexpected(res);
  return { kind: "ok", users: body.users as User[], authMode: body.auth_mode as UserList["auth_mode"] };
}

// Creates a user. Admins only. Without a password, password mode returns an invitation link and oidc mode lets the
// user sign in with the IdP. Errors, including email_taken (409), are shown with the server's message. Never rejects.
export async function createUser(fetch: ApiFetch, input: CreateUserRequest): Promise<CreateUserResult> {
  const sent = await send(fetch, USERS_PATH, jsonInit("POST", input));
  if (sent.kind !== "response") return sent;
  const { res } = sent;
  if (!res.ok) return { kind: "error", message: await responseErrorMessage(res) };
  const body = await okObject(res);
  if (body === null) return unexpected(res);
  const { invitation, ...user } = body as Partial<CreateUserResponse>;
  return { kind: "ok", user: user as User, invitation: invitation ?? null };
}

// Changes the role of a user. Admins only. The updated user in the response is not read: reload the list.
// last_admin (409) is shown with the server's message. Never rejects.
export async function changeUserRole(fetch: ApiFetch, userId: string, role: User["role"]): Promise<UserActionResult> {
  if (!USER_ID_PATTERN.test(userId)) return INVALID_USER_ID;
  return userAction(fetch, userPath(userId), jsonInit("PATCH", { role }));
}

// Sets a new password for a user and ends their sessions and MCP connections (password mode only). Admins only.
// In oidc mode the server also answers 404, which cannot be told apart from a missing user. Never rejects.
export async function resetUserPassword(fetch: ApiFetch, userId: string, password: string): Promise<UserActionResult> {
  if (!USER_ID_PATTERN.test(userId)) return INVALID_USER_ID;
  return userAction(fetch, userPath(userId, "/password"), jsonInit("POST", { password }));
}

// Issues a new invitation link for a user who has not set a password yet (password mode only); the previous link
// stops working. Admins only. notFound means the user is gone (or oidc mode); already_active (409) is shown with the
// server's message. Never rejects.
export async function reissueUserInvitation(fetch: ApiFetch, userId: string): Promise<InvitationResult> {
  if (!USER_ID_PATTERN.test(userId)) return INVALID_USER_ID;
  const sent = await send(fetch, userPath(userId, "/invitation"), { method: "POST" });
  if (sent.kind !== "response") return sent;
  const { res } = sent;
  if (res.ok) {
    const body = await okObject(res);
    if (body === null || typeof body.url !== "string" || typeof body.expires_at !== "number") return unexpected(res);
    return { kind: "ok", invitation: { url: body.url, expires_at: body.expires_at } };
  }
  if (res.status === 404) return { kind: "notFound" };
  return { kind: "error", message: await responseErrorMessage(res) };
}

// Deletes the MFA factors, recovery codes and pending MFA steps of another user, and ends their sessions and MCP
// connections (password mode only). The password stays. Admins only. mfa_not_enrolled (409) and
// cannot_reset_own_mfa (400) are shown with the server's message. Never rejects.
export async function resetUserMfa(fetch: ApiFetch, userId: string): Promise<UserActionResult> {
  if (!USER_ID_PATTERN.test(userId)) return INVALID_USER_ID;
  return userAction(fetch, userPath(userId, "/reset-mfa"), { method: "POST" });
}

// Ends the sessions and MCP connections of a user. Admins only. Never rejects.
export async function revokeUserSessions(fetch: ApiFetch, userId: string): Promise<UserActionResult> {
  if (!USER_ID_PATTERN.test(userId)) return INVALID_USER_ID;
  return userAction(fetch, userPath(userId, "/revoke-sessions"), { method: "POST" });
}

// Deletes a user and their sessions. This cannot be undone. Admins only. cannot_delete_self (400) and last_admin
// (409) are shown with the server's message. Never rejects.
export async function deleteUser(fetch: ApiFetch, userId: string): Promise<UserActionResult> {
  if (!USER_ID_PATTERN.test(userId)) return INVALID_USER_ID;
  return userAction(fetch, userPath(userId), { method: "DELETE" });
}
