// OIDC_REQUIRE_GOOGLE_HD: whether the first association of a user with an OIDC identity (linking an invited user or
// creating the first admin) requires Google's hd claim (the hosted domain of a Google Workspace account). Checked
// by /auth/oidc/callback before the beforeOidcUserLinkOrCreate hook.

export type GoogleHdSetting = "off" | "on" | "invalid";

// OIDC_REQUIRE_GOOGLE_HD. Unset, empty or "false" is off; "true" is on. Read strictly, like
// OIDC_REQUIRE_EMAIL_VERIFIED: no trimming and no case folding, so that a mistake is not taken for either value.
// Not validated by loadConfig: an invalid value only rejects the first association, and the rest of the app keeps
// working.
export function parseGoogleHdSetting(value: unknown): GoogleHdSetting {
  if (value === undefined || value === "" || value === "false") return "off";
  if (value === "true") return "on";
  return "invalid";
}

// Whether the first association of an email with an OIDC identity passes the hd check. A gmail.com address passes
// without hd; any other address needs a non-blank hd. hd is not compared with the domain of the email, so that the
// Workspace of an invited partner is accepted too (a Workspace can also have several domains). googlemail.com is
// not treated as Gmail.
// email must be normalized by the caller (trimmed, lowercased); it is not lowercased here. As a defense, the domain
// is what follows the last @, and a string without @ is not a Gmail address.
export function passesGoogleHd(email: string, claims: Readonly<Record<string, unknown>>): boolean {
  const at = email.lastIndexOf("@");
  if (at !== -1 && email.slice(at + 1) === "gmail.com") return true;
  const hd = claims.hd;
  return typeof hd === "string" && hd.trim() !== "";
}
