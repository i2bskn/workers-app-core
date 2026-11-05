import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import type { CoreBindings } from "../src/config.js";
import { createTestHelpers, type RequestOptions as BaseRequestOptions, type SessionCookies as BaseSessionCookies } from "../src/testing/index.js";
import worker, { BRAND_ID, reset } from "./fixture/src/index.js";

export { PASSWORD, TEST_JWT_SECRET } from "../src/testing/index.js";

export const ORIGIN = "https://app.test";
export const OIDC_ORIGIN = "https://wiki.example.com";

const helpers = createTestHelpers({
  worker,
  env,
  createExecutionContext,
  waitOnExecutionContext,
  brandId: BRAND_ID,
  origin: ORIGIN,
});

export const {
  db,
  send,
  setCookies,
  sessionCookies,
  login,
  createUser,
  dbChangingBefore,
  d1With,
  d1RecordingLargeBinds,
  countTable,
} = helpers;

export type RequestOptions = BaseRequestOptions<Cloudflare.Env>;
export type SessionCookies = BaseSessionCookies<typeof BRAND_ID>;

export const AT = "__Host-testapp_at";
export const RT = "__Host-testapp_rt";
export const OIDC = "__Host-testapp_oidc";

// Deletes every row and removes the hooks of the fixture.
export async function resetDb(): Promise<void> {
  reset();
  await helpers.resetDb(["user_notes"]);
}

// The default allowlist of the OIDC tests: a domain (not "*"), so that the domain match is exercised end to
// end. Every email that the tests sign in with through OIDC is in this domain.
export const OIDC_ALLOWED_EMAILS = "example.com";

export const oidcEnv: Partial<CoreBindings> = {
  AUTH_MODE: "oidc",
  APP_ORIGIN: OIDC_ORIGIN,
  OIDC_ISSUER: "https://idp.example.com",
  OIDC_CLIENT_ID: "test-client",
  OIDC_CLIENT_SECRET: "client-secret",
  ALLOWED_EMAILS: OIDC_ALLOWED_EMAILS,
};

export async function countNotes(userId?: string): Promise<number> {
  const row =
    userId === undefined
      ? await env.DB.prepare("SELECT COUNT(*) AS count FROM user_notes").first<{ count: number }>()
      : await env.DB.prepare("SELECT COUNT(*) AS count FROM user_notes WHERE user_id = ?")
          .bind(userId)
          .first<{ count: number }>();
  return row?.count ?? 0;
}
