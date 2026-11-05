import { describe, expect, it, vi } from "vitest";
import { LoginRequiredError, RefreshFailedError, createApiFetch } from "../../src/client/index.js";

const API_URL = "/api/v1/pages/p1";
const API_INIT: RequestInit = { method: "PATCH", body: JSON.stringify({ version: 1, title: "T" }) };

type Reply = () => Promise<Response>;

function status(code: number): Reply {
  return async () => new Response(code === 204 ? null : `status ${code}`, { status: code });
}

function deferred(): { reply: Reply; resolve: (code: number) => void } {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>((r) => {
    resolve = r;
  });
  return {
    reply: () => promise,
    resolve: (code) => resolve(new Response(code === 204 ? null : `status ${code}`, { status: code })),
  };
}

// Runs every pending microtask.
function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

// fetch that answers API calls and /auth/refresh from separate queues, in order.
function setup({ api, refresh, path = "/" }: { api: Reply[]; refresh?: Reply[]; path?: string }) {
  const apiQueue = [...api];
  const refreshQueue = [...(refresh ?? [])];
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const reply = input === "/auth/refresh" ? refreshQueue.shift() : apiQueue.shift();
    if (!reply) throw new Error(`unexpected fetch: ${String(input)}`);
    return reply();
  });
  const redirectToLogin = vi.fn<(url: string) => void>();
  const apiFetch = createApiFetch({ fetch, redirectToLogin, currentPath: () => path });
  const refreshCalls = () => fetch.mock.calls.filter(([input]) => input === "/auth/refresh");
  return { fetch, redirectToLogin, apiFetch, refreshCalls };
}

describe("createApiFetch", () => {
  it("returns a 200 response without refreshing", async () => {
    const { fetch, apiFetch, refreshCalls } = setup({ api: [status(200)] });
    const res = await apiFetch(API_URL, API_INIT);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("status 200");
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(refreshCalls()).toHaveLength(0);
  });

  it.each([404, 500])("returns a %i response as it is without refreshing", async (code) => {
    const { fetch, apiFetch, redirectToLogin } = setup({ api: [status(code)] });
    const res = await apiFetch(API_URL, API_INIT);
    expect(res.status).toBe(code);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(redirectToLogin).not.toHaveBeenCalled();
  });

  it("refreshes on 401 and retries the same request", async () => {
    const { fetch, apiFetch, redirectToLogin } = setup({ api: [status(401), status(200)], refresh: [status(204)] });
    const res = await apiFetch(API_URL, API_INIT);
    expect(res.status).toBe(200);
    expect(fetch.mock.calls).toEqual([
      [API_URL, API_INIT],
      ["/auth/refresh", { method: "POST" }],
      [API_URL, API_INIT],
    ]);
    const [first, , third] = fetch.mock.calls;
    expect(third?.[0]).toBe(first?.[0]);
    expect(third?.[1]).toBe(first?.[1]);
    expect(third?.[1]?.method).toBe("PATCH");
    expect(third?.[1]?.body).toBe(API_INIT.body);
    expect(redirectToLogin).not.toHaveBeenCalled();
  });

  it("retries after the refresh returns 401, as another tab may have refreshed the cookies", async () => {
    const { apiFetch, redirectToLogin } = setup({ api: [status(401), status(200)], refresh: [status(401)] });
    const res = await apiFetch(API_URL, API_INIT);
    expect(res.status).toBe(200);
    expect(redirectToLogin).not.toHaveBeenCalled();
  });

  it("moves to the login page when the refresh returns 404 on a host other than APP_ORIGIN", async () => {
    const { fetch, apiFetch, redirectToLogin } = setup({
      api: [status(401), status(401)],
      refresh: [status(404)],
      path: "/",
    });
    await expect(apiFetch(API_URL, API_INIT)).rejects.toBeInstanceOf(LoginRequiredError);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(redirectToLogin).toHaveBeenCalledWith("/auth/login?next=%2F");
  });

  it("moves to the login page when the retry returns 401", async () => {
    const { fetch, apiFetch, redirectToLogin } = setup({
      api: [status(401), status(401)],
      refresh: [status(204)],
      path: "/",
    });
    await expect(apiFetch(API_URL, API_INIT)).rejects.toBeInstanceOf(LoginRequiredError);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(redirectToLogin).toHaveBeenCalledTimes(1);
    expect(redirectToLogin).toHaveBeenCalledWith("/auth/login?next=%2F");
  });

  it("encodes the current path and query as next when both the refresh and the retry return 401", async () => {
    const path = "/スペース?a=1&b=2";
    const { apiFetch, redirectToLogin } = setup({
      api: [status(401), status(401)],
      refresh: [status(401)],
      path,
    });
    await expect(apiFetch(API_URL, API_INIT)).rejects.toBeInstanceOf(LoginRequiredError);
    expect(redirectToLogin).toHaveBeenCalledTimes(1);
    expect(redirectToLogin).toHaveBeenCalledWith(`/auth/login?next=${encodeURIComponent(path)}`);
  });

  it("refreshes once for concurrent calls that get 401", async () => {
    const first = deferred();
    const second = deferred();
    const refresh = deferred();
    const { apiFetch, refreshCalls } = setup({
      api: [first.reply, second.reply, status(200), status(200)],
      refresh: [refresh.reply],
    });
    const a = apiFetch(API_URL, API_INIT);
    const b = apiFetch("/api/v1/spaces");
    first.resolve(401);
    second.resolve(401);
    await flush();
    refresh.resolve(204);
    const [resA, resB] = await Promise.all([a, b]);
    expect(resA.status).toBe(200);
    expect(resB.status).toBe(200);
    expect(refreshCalls()).toHaveLength(1);
  });

  it("moves to the login page once for concurrent calls that end with 401", async () => {
    const first = deferred();
    const second = deferred();
    const refresh = deferred();
    const { apiFetch, redirectToLogin, refreshCalls } = setup({
      api: [first.reply, second.reply, status(401), status(401)],
      refresh: [refresh.reply],
    });
    const a = apiFetch(API_URL, API_INIT);
    const b = apiFetch("/api/v1/spaces");
    first.resolve(401);
    second.resolve(401);
    await flush();
    refresh.resolve(204);
    const results = await Promise.allSettled([a, b]);
    for (const result of results) {
      expect(result.status).toBe("rejected");
      if (result.status === "rejected") expect(result.reason).toBeInstanceOf(LoginRequiredError);
    }
    expect(refreshCalls()).toHaveLength(1);
    expect(redirectToLogin).toHaveBeenCalledTimes(1);
  });

  it("refreshes again for a 401 after the previous refresh has finished", async () => {
    const { apiFetch, refreshCalls } = setup({
      api: [status(401), status(200), status(401), status(200)],
      refresh: [status(204), status(204)],
    });
    expect((await apiFetch(API_URL, API_INIT)).status).toBe(200);
    expect((await apiFetch(API_URL, API_INIT)).status).toBe(200);
    expect(refreshCalls()).toHaveLength(2);
  });

  it("rejects with RefreshFailedError without retrying when the refresh returns 500", async () => {
    const { fetch, apiFetch, redirectToLogin } = setup({ api: [status(401)], refresh: [status(500)] });
    const error: unknown = await apiFetch(API_URL, API_INIT).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RefreshFailedError);
    expect((error as RefreshFailedError).status).toBe(500);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(redirectToLogin).not.toHaveBeenCalled();
  });

  it("rejects with the same error when the refresh fetch rejects", async () => {
    const networkError = new TypeError("Failed to fetch");
    const { fetch, apiFetch, redirectToLogin } = setup({
      api: [status(401)],
      refresh: [() => Promise.reject(networkError)],
    });
    await expect(apiFetch(API_URL, API_INIT)).rejects.toBe(networkError);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(redirectToLogin).not.toHaveBeenCalled();
  });
});
