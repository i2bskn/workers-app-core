import { sign, verify } from "hono/jwt";
import * as client from "openid-client";
import type { BrandNames } from "../brand.js";
import type { OidcConfig } from "../config.js";
import { isEmailAllowed, parseAllowlist } from "./allowlist.js";
import { OIDC_COOKIE_TTL_SECONDS } from "./cookies.js";
import { normalizeEmail, normalizeName } from "./validate.js";

export const CALLBACK_PATH = "/auth/oidc/callback";

// Discovery results are cached per isolate. Failed lookups are not cached.
const configurationCache = new Map<string, Promise<client.Configuration>>();

export function getOidcConfiguration(oidc: OidcConfig): Promise<client.Configuration> {
  const key = JSON.stringify([oidc.issuer, oidc.clientId, oidc.clientSecret]);
  let cached = configurationCache.get(key);
  if (!cached) {
    cached = discover(oidc);
    configurationCache.set(key, cached);
    cached.catch(() => configurationCache.delete(key));
  }
  return cached;
}

async function discover(oidc: OidcConfig): Promise<client.Configuration> {
  const discovered = await client.discovery(new URL(oidc.issuer), oidc.clientId);
  const metadata = discovered.serverMetadata();
  // OIDC Discovery defaults to client_secret_basic when the list is absent.
  const methods = metadata.token_endpoint_auth_methods_supported;
  const auth =
    !methods || methods.includes("client_secret_basic")
      ? client.ClientSecretBasic(oidc.clientSecret)
      : client.ClientSecretPost(oidc.clientSecret);
  const configuration = new client.Configuration(metadata, oidc.clientId, undefined, auth);
  // Validate ID token signatures as well (spec 6.4).
  client.enableNonRepudiationChecks(configuration);
  return configuration;
}

export type OidcState = {
  state: string;
  nonce: string;
  codeVerifier: string;
  next: string;
};

export async function signOidcState(
  names: BrandNames,
  value: OidcState,
  secret: string,
  now: number,
): Promise<string> {
  const iat = Math.floor(now / 1000);
  return sign(
    {
      state: value.state,
      nonce: value.nonce,
      code_verifier: value.codeVerifier,
      next: value.next,
      iat,
      exp: iat + OIDC_COOKIE_TTL_SECONDS,
      iss: names.issuer,
      aud: names.oidcAudience,
    },
    secret,
    "HS256",
  );
}

export async function verifyOidcState(
  names: BrandNames,
  token: string,
  secret: string,
  now: number,
): Promise<OidcState | null> {
  let payload: Record<string, unknown>;
  try {
    payload = await verify(token, secret, {
      alg: "HS256",
      iss: names.issuer,
      aud: names.oidcAudience,
      exp: false,
      nbf: false,
      iat: false,
    });
  } catch {
    return null;
  }
  const { state, nonce, code_verifier: codeVerifier, next, exp } = payload;
  if (
    typeof state !== "string" ||
    typeof nonce !== "string" ||
    typeof codeVerifier !== "string" ||
    typeof next !== "string" ||
    typeof exp !== "number" ||
    exp * 1000 <= now
  ) {
    return null;
  }
  return { state, nonce, codeVerifier, next };
}

// Builds the authorization request. Returns the IdP URL and the signed state to store in the cookie.
export async function startOidcLogin(
  names: BrandNames,
  oidc: OidcConfig,
  secret: string,
  next: string,
  now: number,
): Promise<{ authorizationUrl: URL; stateToken: string }> {
  const configuration = await getOidcConfiguration(oidc);
  const state: OidcState = {
    state: client.randomState(),
    nonce: client.randomNonce(),
    codeVerifier: client.randomPKCECodeVerifier(),
    next,
  };
  const authorizationUrl = client.buildAuthorizationUrl(configuration, {
    redirect_uri: `${oidc.appOrigin}${CALLBACK_PATH}`,
    scope: "openid email profile",
    response_type: "code",
    state: state.state,
    nonce: state.nonce,
    code_challenge: await client.calculatePKCECodeChallenge(state.codeVerifier),
    code_challenge_method: "S256",
  });
  return { authorizationUrl, stateToken: await signOidcState(names, state, secret, now) };
}

// Exchanges the code and validates the ID token (signature, iss, aud, exp, nonce) with openid-client.
export async function exchangeCode(
  oidc: OidcConfig,
  callbackSearch: string,
  state: OidcState,
): Promise<Record<string, unknown>> {
  const configuration = await getOidcConfiguration(oidc);
  const currentUrl = new URL(`${oidc.appOrigin}${CALLBACK_PATH}${callbackSearch}`);
  const tokens = await client.authorizationCodeGrant(configuration, currentUrl, {
    pkceCodeVerifier: state.codeVerifier,
    expectedNonce: state.nonce,
    expectedState: state.state,
  });
  const claims = tokens.claims();
  if (!claims) throw new Error("ID token is missing from the token response");
  return claims;
}

// When requireEmailVerified is false, a missing email_verified claim is accepted.
// A claim that is present must still be the boolean true.
export function isEmailVerified(claims: Record<string, unknown>, requireEmailVerified: boolean): boolean {
  const absent = !("email_verified" in claims) || claims.email_verified === undefined;
  if (absent) return !requireEmailVerified;
  return claims.email_verified === true;
}

export type ClaimsResult =
  | { ok: true; email: string; name: string | null }
  | { ok: false; reason: "invalid_email" | "email_not_verified" | "not_allowed" };

// Spec 6.4 steps 4-7. The email comes from the ID token only.
export function evaluateIdTokenClaims(
  claims: Record<string, unknown>,
  options: Pick<OidcConfig, "allowedEmails" | "requireEmailVerified">,
): ClaimsResult {
  const email = normalizeEmail(claims.email);
  if (email === null) return { ok: false, reason: "invalid_email" };
  if (!isEmailVerified(claims, options.requireEmailVerified)) return { ok: false, reason: "email_not_verified" };
  if (!isEmailAllowed(email, parseAllowlist(options.allowedEmails))) return { ok: false, reason: "not_allowed" };
  const name = normalizeName(claims.name);
  return { ok: true, email, name: name.ok ? name.value : null };
}
