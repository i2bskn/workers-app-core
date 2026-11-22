import { describe, expect, it } from "vitest";
import { withDefaultSecurityHeaders } from "../src/auth/middleware.js";

describe("withDefaultSecurityHeaders", () => {
  it("keeps the values that the response already has", async () => {
    const res = withDefaultSecurityHeaders(
      new Response("body", { status: 201, statusText: "Created", headers: { "Referrer-Policy": "no-referrer" } }),
    );
    expect(res.status).toBe(201);
    expect(res.statusText).toBe("Created");
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(await res.text()).toBe("body");
  });

  it("keeps every Set-Cookie", () => {
    const headers = new Headers();
    headers.append("Set-Cookie", "a=1; Path=/");
    headers.append("Set-Cookie", "b=2; Path=/");
    const res = withDefaultSecurityHeaders(new Response(null, { status: 303, headers }));
    expect(res.headers.getSetCookie()).toEqual(["a=1; Path=/", "b=2; Path=/"]);
    expect(res.headers.get("Referrer-Policy")).toBe("same-origin");
  });

  it("returns a WebSocket upgrade as is", () => {
    const [client] = Object.values(new WebSocketPair());
    const upgrade = new Response(null, { status: 101, webSocket: client });
    expect(withDefaultSecurityHeaders(upgrade)).toBe(upgrade);
  });
});
