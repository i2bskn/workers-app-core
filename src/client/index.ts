// Browser-safe: imports no server module. Types only from the API types.
import type { ApiError } from "../api-types.js";

export type { ApiError, User, UserList } from "../api-types.js";

// Login is required and the move to the login page has started.
export class LoginRequiredError extends Error {
  constructor() {
    super("login required");
    this.name = "LoginRequiredError";
  }
}

// Refreshing the tokens failed with a response other than 204 and 4xx (e.g. 5xx).
export class RefreshFailedError extends Error {
  readonly status: number;

  constructor(status: number) {
    super(`token refresh failed with HTTP ${status}`);
    this.name = "RefreshFailedError";
    this.status = status;
  }
}

export type ApiFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export type ApiFetchOptions = {
  fetch: typeof globalThis.fetch;
  redirectToLogin: (url: string) => void;
  // Path and query of the current page, used as `next` of the login page.
  currentPath: () => string;
};

// fetch for hc() that refreshes the access token cookie (valid for 15 minutes) on 401 and retries once.
// Responses other than 401, including 4xx and 5xx, are returned as they are.
export function createApiFetch({ fetch, redirectToLogin, currentPath }: ApiFetchOptions): ApiFetch {
  // Shared by calls that get 401 at the same time, and released once settled.
  let refreshing: Promise<void> | null = null;
  let redirected = false;

  function refresh(): Promise<void> {
    refreshing ??= (async () => {
      const res = await fetch("/auth/refresh", { method: "POST" });
      // 4xx also goes on to the retry, which ends at the login page if it still gets 401:
      // - 401: another tab may have refreshed first and replaced the cookies (the server rejects the
      //   just-rotated refresh token with 401 without clearing them).
      // - 404: in oidc mode, unifyHost answers POSTs on hosts other than APP_ORIGIN with 404; the login
      //   page then redirects to APP_ORIGIN.
      if (res.status !== 204 && (res.status < 400 || res.status >= 500)) throw new RefreshFailedError(res.status);
    })().finally(() => {
      refreshing = null;
    });
    return refreshing;
  }

  return async (input, init) => {
    const first = await fetch(input, init);
    if (first.status !== 401) return first;
    await refresh();
    const second = await fetch(input, init);
    if (second.status !== 401) return second;
    if (!redirected) {
      redirected = true;
      redirectToLogin(`/auth/login?next=${encodeURIComponent(currentPath())}`);
    }
    throw new LoginRequiredError();
  };
}

export function isApiError(value: unknown): value is ApiError {
  if (typeof value !== "object" || value === null) return false;
  const error = (value as { error?: unknown }).error;
  return typeof error === "object" && error !== null && typeof (error as { message?: unknown }).message === "string";
}

export function unexpectedResponseMessage(status: number): string {
  return `サーバーから予期しない応答がありました（HTTP ${status}）`;
}

// The message to show for a response that is not ok.
export async function responseErrorMessage(res: { status: number; json(): Promise<unknown> }): Promise<string> {
  try {
    const body: unknown = await res.json();
    if (isApiError(body)) return body.error.message;
  } catch {
    // Not JSON.
  }
  return unexpectedResponseMessage(res.status);
}
