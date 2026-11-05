export function parseAllowlist(value: string): string[] {
  return value
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry !== "");
}

// An entry that allows every email, for when the IdP itself restricts who can sign in.
const ALLOW_ALL = "*";

// `email` must already be normalized. An empty list allows no one. An entry that is exactly "*" allows
// everyone; "*" inside an entry (e.g. "*@example.com") is not a wildcard and is compared as is. Other entries
// match the whole email when they contain "@", otherwise the domain exactly (subdomains do not match).
export function isEmailAllowed(email: string, allowlist: string[]): boolean {
  if (allowlist.includes(ALLOW_ALL)) return true;
  if (allowlist.length === 0) return false;
  const normalized = email.toLowerCase();
  const domain = normalized.slice(normalized.lastIndexOf("@") + 1);
  return allowlist.some((entry) => (entry.includes("@") ? entry === normalized : entry === domain));
}
