import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { CookieOptions } from "hono/utils/cookie";
import type { BrandNames } from "../brand.js";
import type { NewSession } from "./sessions.js";
import { ACCESS_TOKEN_TTL_SECONDS, signAccessToken } from "./tokens.js";

export const OIDC_COOKIE_TTL_SECONDS = 10 * 60;

const baseOptions: CookieOptions = {
  prefix: "host",
  httpOnly: true,
  secure: true,
  sameSite: "Lax",
  path: "/",
};

type AnyContext = Context<any>;

export function getAccessCookie(names: BrandNames, c: AnyContext): string | undefined {
  return getCookie(c, names.accessCookie, "host");
}

export function getRefreshCookie(names: BrandNames, c: AnyContext): string | undefined {
  return getCookie(c, names.refreshCookie, "host");
}

export function setSessionCookies(
  names: BrandNames,
  c: AnyContext,
  tokens: { accessToken: string; refreshToken: string; familyExpiresAt: number },
  now: number,
): void {
  setCookie(c, names.accessCookie, tokens.accessToken, { ...baseOptions, maxAge: ACCESS_TOKEN_TTL_SECONDS });
  const refreshMaxAge = Math.max(0, Math.floor((tokens.familyExpiresAt - now) / 1000));
  setCookie(c, names.refreshCookie, tokens.refreshToken, { ...baseOptions, maxAge: refreshMaxAge });
}

// Signs an access token for the session and sets both session cookies.
export async function setCookiesForSession(
  names: BrandNames,
  c: AnyContext,
  session: NewSession,
  secret: string,
  now: number,
): Promise<void> {
  const accessToken = await signAccessToken(names, { sub: session.userId, sid: session.sessionId }, secret, now);
  setSessionCookies(
    names,
    c,
    { accessToken, refreshToken: session.refreshToken, familyExpiresAt: session.familyExpiresAt },
    now,
  );
}

export function clearSessionCookies(names: BrandNames, c: AnyContext): void {
  deleteCookie(c, names.accessCookie, baseOptions);
  deleteCookie(c, names.refreshCookie, baseOptions);
}

export function getOidcCookie(names: BrandNames, c: AnyContext): string | undefined {
  return getCookie(c, names.oidcCookie, "host");
}

export function setOidcCookie(names: BrandNames, c: AnyContext, value: string): void {
  setCookie(c, names.oidcCookie, value, { ...baseOptions, maxAge: OIDC_COOKIE_TTL_SECONDS });
}

export function clearOidcCookie(names: BrandNames, c: AnyContext): void {
  deleteCookie(c, names.oidcCookie, baseOptions);
}
