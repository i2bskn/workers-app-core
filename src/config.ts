import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { Db } from "./db/client.js";
import type { UserRow } from "./db/schema.js";

// The bindings the package reads. Apps extend this type with their own.
export type CoreBindings = {
  DB: D1Database;
  OAUTH_KV: KVNamespace;
  // Set by OAuthProvider before it calls the Hono app. Absent when the request origin cannot host
  // OAuth (plain http on a non-loopback host), in which case the app is called directly.
  OAUTH_PROVIDER?: OAuthHelpers;
  AUTH_MODE?: string;
  JWT_SECRET?: string;
  APP_ORIGIN?: string;
  OIDC_ISSUER?: string;
  OIDC_CLIENT_ID?: string;
  OIDC_CLIENT_SECRET?: string;
  ALLOWED_EMAILS?: string;
  OIDC_REQUIRE_EMAIL_VERIFIED?: string;
};

export type AuthMode = "oidc" | "password";

export type OidcConfig = {
  appOrigin: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  allowedEmails: string;
  requireEmailVerified: boolean;
};

export type Config = {
  authMode: AuthMode;
  jwtSecret: string;
  oidc: OidcConfig | null;
};

// The variables set by the package's middleware. user and sessionId are set by requireUser.
export type CoreVariables = {
  config: Config;
  db: Db;
  user: UserRow;
  sessionId: string;
};

// The Hono environment of an app: its bindings, and the package's variables with its own.
export type AppEnv<AppBindings extends CoreBindings = CoreBindings, AppVariables extends object = {}> = {
  Bindings: AppBindings;
  Variables: CoreVariables & AppVariables;
};

const DEFAULT_AUTH_MODE: AuthMode = "password";
const MIN_JWT_SECRET_LENGTH = 32;

export type ConfigResult = { ok: true; config: Config } | { ok: false; invalid: string[] };

export function loadConfig(env: CoreBindings): ConfigResult {
  const invalid: string[] = [];

  const mode = env.AUTH_MODE === undefined || env.AUTH_MODE === "" ? DEFAULT_AUTH_MODE : env.AUTH_MODE;
  if (mode !== "oidc" && mode !== "password") {
    invalid.push("AUTH_MODE");
  }

  const jwtSecret = env.JWT_SECRET ?? "";
  if (jwtSecret.length < MIN_JWT_SECRET_LENGTH) {
    invalid.push("JWT_SECRET");
  }

  if (!env.DB) {
    invalid.push("DB");
  }

  let oidc: OidcConfig | null = null;
  if (mode === "oidc") {
    const appOrigin = parseAppOrigin(env.APP_ORIGIN);
    if (appOrigin === null) invalid.push("APP_ORIGIN");
    const issuer = parseHttpsUrl(env.OIDC_ISSUER);
    if (issuer === null) invalid.push("OIDC_ISSUER");
    const clientId = env.OIDC_CLIENT_ID ?? "";
    if (clientId === "") invalid.push("OIDC_CLIENT_ID");
    const clientSecret = env.OIDC_CLIENT_SECRET ?? "";
    if (clientSecret === "") invalid.push("OIDC_CLIENT_SECRET");
    const requireEmailVerified = parseRequireEmailVerified(env.OIDC_REQUIRE_EMAIL_VERIFIED);
    if (requireEmailVerified === null) invalid.push("OIDC_REQUIRE_EMAIL_VERIFIED");
    if (appOrigin !== null && issuer !== null && requireEmailVerified !== null) {
      oidc = {
        appOrigin,
        issuer,
        clientId,
        clientSecret,
        allowedEmails: env.ALLOWED_EMAILS ?? "",
        requireEmailVerified,
      };
    }
  }

  if (invalid.length > 0) {
    return { ok: false, invalid };
  }
  return { ok: true, config: { authMode: mode as AuthMode, jwtSecret, oidc } };
}

// Unset, "" and "true" require email_verified. Only the exact string "false" relaxes it.
// Any other value (including non-string values from JSON variables) is a configuration error.
function parseRequireEmailVerified(value: unknown): boolean | null {
  if (value === undefined) return true;
  if (typeof value !== "string") return null;
  if (value === "" || value === "true") return true;
  if (value === "false") return false;
  return null;
}

function parseAppOrigin(value: string | undefined): string | null {
  if (!value) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (value !== url.origin && value !== `${url.origin}/`) return null;
  return url.origin;
}

function parseHttpsUrl(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" ? value : null;
  } catch {
    return null;
  }
}
