import type { Role } from "./auth/validate.js";
import type { AuthMode } from "./config.js";

export type User = {
  id: string;
  email: string;
  name: string | null;
  role: Role;
  // UNIX time in milliseconds.
  created_at: number;
  // UNIX time in milliseconds.
  last_login_at: number | null;
  // "invited" until the user can sign in for the first time: in password mode while no password is set, in oidc mode
  // while no OIDC identity is linked.
  status: "active" | "invited";
};

// An invitation link of password mode. The URL holds the token and is returned only when it is issued.
export type Invitation = {
  url: string;
  // UNIX time in milliseconds.
  expires_at: number;
};

// The response of POST /api/v1/users. invitation is set only in password mode when no password was given.
export type CreateUserResponse = User & { invitation: Invitation | null };

export type UserList = {
  users: User[];
  // The screen hides the operations that exist only in password mode.
  auth_mode: AuthMode;
};

export type ApiError = {
  error: {
    // snake_case error code, e.g. `invalid_email`, `not_found`.
    code: string;
    message: string;
    // The reason for each invalid item, keyed by the item name. Only on validation errors.
    fields?: Record<string, string>;
  };
};

export type ChangeMyPasswordRequest = {
  current_password: string;
  new_password: string;
};

export type CreateUserRequest = {
  email: string;
  name?: string | null;
  // Omitted or null: no password. In password mode, the user is invited with a link; in oidc mode, a password is
  // never accepted.
  password?: string | null;
  role: Role;
};

// CreateUserRequest after validation. email is normalized, a missing or blank name is null, and a missing password
// is null.
export type CreateUserInput = {
  email: string;
  name: string | null;
  password: string | null;
  role: Role;
};

export type ResetPasswordRequest = {
  password: string;
};

export type UpdateUserRequest = {
  role: Role;
};
