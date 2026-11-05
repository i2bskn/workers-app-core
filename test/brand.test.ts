import { beforeEach, describe, expect, it } from "vitest";
import { brandNames } from "../src/brand.js";
import { signOidcState } from "../src/auth/oidc.js";
import { createCore } from "../src/index.js";
import { mcp } from "./fixture/src/index.js";
import { createUser, login, resetDb, AT, RT, TEST_JWT_SECRET } from "./helpers.js";

function payload(jwt: string): Record<string, unknown> {
  const part = jwt.split(".")[1] ?? "";
  return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
}

function core(id: string) {
  return createCore({ brand: { id, name: "Name" }, mcp, consent: { description: "text" } });
}

beforeEach(resetDb);

describe("brand id", () => {
  it.each([["a"], ["querune"], ["my-app2"], [`a${"b".repeat(30)}`]])("accepts %j", (id) => {
    expect(() => core(id)).not.toThrow();
  });

  it.each([[""], ["1app"], ["-app"], ["App"], ["my_app"], ["my app"], [`a${"b".repeat(31)}`], ["app/x"]])(
    "rejects %j",
    (id) => {
      expect(() => core(id)).toThrow(/invalid brand id/);
    },
  );

  it("requires consent.description or consent.render", () => {
    expect(() => createCore({ brand: { id: "app", name: "App" }, mcp, consent: {} })).toThrow(/consent/);
    expect(() =>
      createCore({ brand: { id: "app", name: "App" }, mcp, consent: { render: () => Promise.resolve("" as never) } }),
    ).not.toThrow();
  });
});

describe("derived names", () => {
  it("derives the cookie and JWT names from the id", () => {
    expect(brandNames("querune")).toEqual({
      accessCookie: "querune_at",
      refreshCookie: "querune_rt",
      oidcCookie: "querune_oidc",
      issuer: "querune",
      accessAudience: "querune-web",
      oidcAudience: "querune-oidc",
    });
  });

  it("names the session cookies and the access token after the brand", async () => {
    const user = await createUser({ email: "alice@example.com" });
    const cookies = await login(user.email);
    expect(Object.keys(cookies).sort()).toEqual([AT, RT].sort());
    expect(payload(cookies[AT])).toMatchObject({ iss: "testapp", aud: "testapp-web", sub: user.id });
  });

  it("signs and verifies access tokens only for the same brand", async () => {
    const a = core("brand-a");
    const b = core("brand-b");
    const now = Date.now();
    const token = await a.signAccessToken({ sub: "u", sid: "s" }, TEST_JWT_SECRET, now);
    expect(payload(token)).toMatchObject({ iss: "brand-a", aud: "brand-a-web" });
    expect(await a.verifyAccessToken(token, TEST_JWT_SECRET, now)).toMatchObject({ sub: "u", sid: "s" });
    expect(await b.verifyAccessToken(token, TEST_JWT_SECRET, now)).toBeNull();
  });

  it("names the OIDC state token after the brand", async () => {
    const token = await signOidcState(
      brandNames("brand-a"),
      { state: "s", nonce: "n", codeVerifier: "v", next: "/" },
      TEST_JWT_SECRET,
      Date.now(),
    );
    expect(payload(token)).toMatchObject({ iss: "brand-a", aud: "brand-a-oidc" });
  });
});
