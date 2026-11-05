export type Role = "admin" | "member";

const EMAIL_MAX_LENGTH = 254;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NAME_MAX_LENGTH = 100;
const PASSWORD_MIN_LENGTH = 12;
const PASSWORD_MAX_LENGTH = 256;

function codePointLength(value: string): number {
  return [...value].length;
}

// Returns the normalized email, or null if invalid.
export function normalizeEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  if (codePointLength(email) > EMAIL_MAX_LENGTH || !EMAIL_PATTERN.test(email)) return null;
  return email;
}

// undefined and null are treated as "no name".
export function normalizeName(value: unknown): { ok: true; value: string | null } | { ok: false } {
  if (value === undefined || value === null) return { ok: true, value: null };
  if (typeof value !== "string") return { ok: false };
  const name = value.trim();
  if (name === "") return { ok: true, value: null };
  if (codePointLength(name) > NAME_MAX_LENGTH) return { ok: false };
  return { ok: true, value: name };
}

export function isRole(value: unknown): value is Role {
  return value === "admin" || value === "member";
}

export function isValidPassword(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const length = codePointLength(value);
  return length >= PASSWORD_MIN_LENGTH && length <= PASSWORD_MAX_LENGTH;
}

export function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
