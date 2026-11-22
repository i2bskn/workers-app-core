import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { Db } from "./db/client.js";
import type { UserRow } from "./db/schema.js";
import { normalizeEmail } from "./auth/validate.js";

// The bindings the package reads. Apps extend this type with their own.
export type CoreBindings = {
  DB: D1Database;
  OAUTH_KV: KVNamespace;
  // Set by OAuthProvider before it calls the Hono app. Absent when the request origin cannot host
  // OAuth (plain http on a non-loopback host), in which case the app is called directly.
  OAUTH_PROVIDER?: OAuthHelpers;
  AUTH_MODE?: string;
  PASSWORD_MFA_POLICY?: string;
  PASSWORD_MFA_KEY?: string;
  JWT_SECRET?: string;
  APP_ORIGIN?: string;
  OIDC_ISSUER?: string;
  OIDC_CLIENT_ID?: string;
  OIDC_CLIENT_SECRET?: string;
  INITIAL_ADMIN_EMAIL?: string;
  OIDC_REQUIRE_EMAIL_VERIFIED?: string;
  // Read by /auth/oidc/callback on each first association, not by loadConfig (see src/auth/google-hd.ts).
  OIDC_REQUIRE_GOOGLE_HD?: string;
  SESSION_MAX_AGE_HOURS?: string;
  SESSION_IDLE_TIMEOUT_HOURS?: string;
  // Optional Rate Limiting binding that limits POST /auth/login per email address.
  LOGIN_RATE_LIMITER?: LoginRateLimiter;
};

// The part of a Workers Rate Limiting binding that the package uses. A RateLimit binding can be assigned to it.
export type LoginRateLimiter = {
  limit(options: { key: string }): Promise<{ success: boolean }>;
};

export type AuthMode = "oidc" | "password";

export type PasswordMfaConfig = {
  policy: "optional" | "admins" | "all";
  origin: string | null;
  key: string | null;
};

export type OidcConfig = {
  appOrigin: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  // While there are no users, the first sign-in with this email creates the first admin. Null when unset.
  initialAdminEmail: string | null;
  requireEmailVerified: boolean;
};

// The lifetime of web sessions. maxAgeMs is the absolute expiry from the sign-in; idleTimeoutMs, when set, is the
// limit from the last refresh.
export type SessionConfig = { maxAgeMs: number; idleTimeoutMs: number | null };

export type Config = {
  authMode: AuthMode;
  jwtSecret: string;
  oidc: OidcConfig | null;
  passwordMfa: PasswordMfaConfig;
  session: SessionConfig;
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
const HOUR_MS = 60 * 60 * 1000;
const DEFAULT_SESSION_MAX_AGE_HOURS: Record<AuthMode, number> = {
  password: 720,
  oidc: 24,
};
// 400 days: hono's setCookie throws for a Max-Age above 34,560,000 seconds.
const MAX_SESSION_HOURS = 9600;

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
    const issuer = parseOidcIssuer(env.OIDC_ISSUER);
    if (issuer === null) invalid.push("OIDC_ISSUER");
    const clientId = env.OIDC_CLIENT_ID ?? "";
    if (clientId === "") invalid.push("OIDC_CLIENT_ID");
    const clientSecret = env.OIDC_CLIENT_SECRET ?? "";
    if (clientSecret === "") invalid.push("OIDC_CLIENT_SECRET");
    const requireEmailVerified = parseRequireEmailVerified(env.OIDC_REQUIRE_EMAIL_VERIFIED);
    if (requireEmailVerified === null) invalid.push("OIDC_REQUIRE_EMAIL_VERIFIED");
    const initialAdminEmail = parseInitialAdminEmail(env.INITIAL_ADMIN_EMAIL);
    if (initialAdminEmail === undefined) invalid.push("INITIAL_ADMIN_EMAIL");
    if (appOrigin !== null && issuer !== null && requireEmailVerified !== null && initialAdminEmail !== undefined) {
      oidc = {
        appOrigin,
        issuer,
        clientId,
        clientSecret,
        initialAdminEmail,
        requireEmailVerified,
      };
    }
  }

  const passwordMfa: PasswordMfaConfig = { policy: "optional", origin: null, key: null };
  if (mode === "password") {
    const policy = env.PASSWORD_MFA_POLICY === undefined || env.PASSWORD_MFA_POLICY === ""
      ? "optional"
      : env.PASSWORD_MFA_POLICY;
    if (policy === "optional" || policy === "admins" || policy === "all") passwordMfa.policy = policy;
    else invalid.push("PASSWORD_MFA_POLICY");
    if (env.APP_ORIGIN !== undefined && env.APP_ORIGIN !== "") {
      // Only a canonical HTTPS origin enables WebAuthn; other password deployments still work.
      passwordMfa.origin = parseAppOrigin(env.APP_ORIGIN);
    }
    if (env.PASSWORD_MFA_KEY !== undefined && env.PASSWORD_MFA_KEY !== "") {
      // Exactly 32 bytes in standard padded base64 (openssl rand -base64 32).
      if (typeof env.PASSWORD_MFA_KEY === "string" && /^[A-Za-z0-9+/]{43}=$/.test(env.PASSWORD_MFA_KEY)) {
        passwordMfa.key = env.PASSWORD_MFA_KEY;
      } else {
        invalid.push("PASSWORD_MFA_KEY");
      }
    }
    if (passwordMfa.policy !== "optional" && !passwordMfa.origin && !passwordMfa.key) {
      invalid.push("APP_ORIGIN or PASSWORD_MFA_KEY");
    }
  }

  const maxAgeHours = parseSessionHours(env.SESSION_MAX_AGE_HOURS);
  if (maxAgeHours === null) invalid.push("SESSION_MAX_AGE_HOURS");
  const idleTimeoutHours = parseSessionHours(env.SESSION_IDLE_TIMEOUT_HOURS);
  if (idleTimeoutHours === null) invalid.push("SESSION_IDLE_TIMEOUT_HOURS");

  if (invalid.length > 0 || maxAgeHours === null || idleTimeoutHours === null) {
    return { ok: false, invalid };
  }
  const authMode = mode as AuthMode;
  const session: SessionConfig = {
    maxAgeMs: (maxAgeHours === undefined ? DEFAULT_SESSION_MAX_AGE_HOURS[authMode] : maxAgeHours) * HOUR_MS,
    idleTimeoutMs: idleTimeoutHours === undefined ? null : idleTimeoutHours * HOUR_MS,
  };
  return { ok: true, config: { authMode, jwtSecret, oidc, passwordMfa, session } };
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

// Unset and "" mean no initial admin (null). An email is normalized. Any other value (including non-string values
// from JSON variables) is a configuration error (undefined).
function parseInitialAdminEmail(value: unknown): string | null | undefined {
  if (value === undefined || value === "") return null;
  if (typeof value !== "string") return undefined;
  return normalizeEmail(value) ?? undefined;
}

// Unset and "" mean the default (undefined). A whole number of hours from 1 to MAX_SESSION_HOURS, written without
// signs, leading zeros or spaces, is accepted. Any other value (including non-string values from JSON variables) is
// a configuration error (null).
function parseSessionHours(value: unknown): number | undefined | null {
  if (value === undefined || value === "") return undefined;
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) return null;
  const hours = Number(value);
  return hours <= MAX_SESSION_HOURS ? hours : null;
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

// An https URL that is not a discovery document: openid-client does not check the issuer of such a URL.
function parseOidcIssuer(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:") return null;
    return url.href.includes("/.well-known/") ? null : value;
  } catch {
    return null;
  }
}
