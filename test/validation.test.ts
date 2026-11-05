import { describe, expect, it } from "vitest";
import { isEmailAllowed, parseAllowlist } from "../src/auth/allowlist.js";
import { safeNext } from "../src/auth/redirect.js";
import { isRole, isValidPassword, normalizeEmail, normalizeName } from "../src/auth/validate.js";
import { ORIGIN, send } from "./helpers.js";

describe("allowlist", () => {
  const allowed = (email: string, list: string) => isEmailAllowed(email, parseAllowlist(list));

  it("allows no one when empty", () => {
    expect(allowed("a@example.com", "")).toBe(false);
    expect(allowed("a@example.com", " , ,")).toBe(false);
  });

  it("allows everyone with a * entry", () => {
    expect(allowed("a@example.com", "*")).toBe(true);
    expect(allowed("a@other.com", " * ")).toBe(true);
    expect(allowed("a@other.com", "*,example.com")).toBe(true);
    expect(allowed("a@other.com", "example.com, *")).toBe(true);
  });

  it("does not treat * inside an entry as a wildcard", () => {
    expect(allowed("a@example.com", "*@example.com")).toBe(false);
    expect(allowed("a@example.com", "*.com")).toBe(false);
  });

  it("matches domains exactly", () => {
    expect(allowed("a@example.com", "example.com")).toBe(true);
    expect(allowed("a@other.com", "example.com")).toBe(false);
  });

  it("does not match subdomains", () => {
    expect(allowed("a@sub.example.com", "example.com")).toBe(false);
    expect(allowed("a@evilexample.com", "example.com")).toBe(false);
  });

  it("matches email addresses exactly", () => {
    expect(allowed("alice@example.org", "example.com, alice@example.org")).toBe(true);
    expect(allowed("bob@example.org", "example.com, alice@example.org")).toBe(false);
  });

  it("ignores case and surrounding whitespace", () => {
    expect(allowed("alice@example.org", "  ALICE@Example.ORG ")).toBe(true);
    expect(allowed("bob@example.com", " Example.COM ")).toBe(true);
  });
});

describe("safeNext", () => {
  it("keeps same-origin paths", () => {
    expect(safeNext("/a?b#c", ORIGIN)).toBe("/a?b#c");
    expect(safeNext("/wiki/page", ORIGIN)).toBe("/wiki/page");
  });

  it.each([
    ["//evil"],
    ["/\\evil"],
    ["https://evil"],
    [""],
    ["/\t/evil"],
    ["/\n/evil"],
    ["/ /evil"],
    ["/\u007f/evil"],
    ["evil"],
  ])("replaces %j with /", (next) => {
    expect(safeNext(next, ORIGIN)).toBe("/");
  });

  it("replaces a missing value with /", () => {
    expect(safeNext(undefined, ORIGIN)).toBe("/");
    expect(safeNext(null, ORIGIN)).toBe("/");
  });

  it("rejects /%09/evil after query decoding", async () => {
    // The query parameter decodes to "/\t/evil".
    const res = await send("/auth/login?next=/%09/evil", { method: "POST", form: { email: "x", password: "y" } });
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('name="next" value="/"');
  });
});

describe("input validation", () => {
  it("normalizes and validates email", () => {
    expect(normalizeEmail("  Alice@Example.COM ")).toBe("alice@example.com");
    expect(normalizeEmail("a@b.c")).toBe("a@b.c");
    expect(normalizeEmail("a@b")).toBeNull();
    expect(normalizeEmail("a b@example.com")).toBeNull();
    expect(normalizeEmail("a@@example.com")).toBeNull();
    expect(normalizeEmail("")).toBeNull();
    expect(normalizeEmail(123)).toBeNull();
    const local = "a".repeat(64);
    const at254 = `${local}@${"b".repeat(254 - local.length - 1 - 4)}.com`;
    expect(at254).toHaveLength(254);
    expect(normalizeEmail(at254)).toBe(at254);
    expect(normalizeEmail(`a${at254}`)).toBeNull();
  });

  it("normalizes and validates name", () => {
    expect(normalizeName("  Alice  ")).toEqual({ ok: true, value: "Alice" });
    expect(normalizeName("   ")).toEqual({ ok: true, value: null });
    expect(normalizeName(undefined)).toEqual({ ok: true, value: null });
    expect(normalizeName(null)).toEqual({ ok: true, value: null });
    expect(normalizeName("あ".repeat(100))).toEqual({ ok: true, value: "あ".repeat(100) });
    expect(normalizeName("あ".repeat(101))).toEqual({ ok: false });
    expect(normalizeName(` ${"a".repeat(100)} `)).toEqual({ ok: true, value: "a".repeat(100) });
    expect(normalizeName(1)).toEqual({ ok: false });
  });

  it("validates role", () => {
    expect(isRole("admin")).toBe(true);
    expect(isRole("member")).toBe(true);
    expect(isRole("Admin")).toBe(false);
    expect(isRole("owner")).toBe(false);
    expect(isRole(undefined)).toBe(false);
  });

  it("validates password length in code points", () => {
    expect(isValidPassword("a".repeat(11))).toBe(false);
    expect(isValidPassword("a".repeat(12))).toBe(true);
    expect(isValidPassword("a".repeat(256))).toBe(true);
    expect(isValidPassword("a".repeat(257))).toBe(false);
    // 12 emoji are 24 UTF-16 code units but 12 code points.
    expect(isValidPassword("😀".repeat(12))).toBe(true);
    expect(isValidPassword("😀".repeat(11))).toBe(false);
    expect(isValidPassword(123456789012)).toBe(false);
  });
});
