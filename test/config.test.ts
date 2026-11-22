import { describe, expect, it } from "vitest";
import { env as workerEnv } from "cloudflare:workers";
import { loadConfig, type CoreBindings } from "../src/config.js";
import { oidcEnv } from "./helpers.js";

const HOUR = 60 * 60 * 1000;

describe("password MFA configuration", () => {
  const load = (settings: Partial<CoreBindings>) => loadConfig({ ...workerEnv, ...settings });

  it("offers voluntary enrollment by default", () => {
    const result = load({});
    expect(result.ok && result.config.passwordMfa).toEqual({ policy: "optional", key: null, origin: null });
  });

  it("requires at least one configured method for enforced enrollment", () => {
    expect(load({ PASSWORD_MFA_POLICY: "admins" }).ok).toBe(false);
    expect(load({ PASSWORD_MFA_POLICY: "admins", APP_ORIGIN: "https://wiki.test" }).ok).toBe(true);
    expect(load({ PASSWORD_MFA_POLICY: "all", PASSWORD_MFA_KEY: btoa("x".repeat(32)) }).ok).toBe(true);
  });

  it.each(["http://localhost:8787", "https://wiki.test/path"])("keeps existing password deployments usable with %s", (origin) => {
    const settings = { APP_ORIGIN: origin };
    const optional = load(settings);
    expect(optional.ok && optional.config.passwordMfa.origin).toBeNull();
    expect(load({ ...settings, PASSWORD_MFA_POLICY: "all" }).ok).toBe(false);
    expect(load({ ...settings, PASSWORD_MFA_POLICY: "all", PASSWORD_MFA_KEY: btoa("x".repeat(32)) }).ok).toBe(true);
    expect(load({ ...oidcEnv, ...settings }).ok).toBe(false);
  });

  it("rejects unknown policy or invalid encryption key in password mode only", () => {
    for (const setting of [
      { PASSWORD_MFA_POLICY: "sometimes" },
      { PASSWORD_MFA_POLICY: false as unknown as string },
      { PASSWORD_MFA_KEY: "short" },
    ]) expect(load(setting).ok).toBe(false);
    expect(load({ ...oidcEnv, PASSWORD_MFA_POLICY: "invalid", PASSWORD_MFA_KEY: "unused" }).ok).toBe(true);
  });
});

describe("loadConfig session lifetime", () => {
  const load = (overrides: Partial<CoreBindings>) => loadConfig({ ...workerEnv, ...overrides } as CoreBindings);
  const loadOidc = (overrides: Partial<CoreBindings>) =>
    loadConfig({ ...workerEnv, ...oidcEnv, ...overrides } as CoreBindings);

  it("defaults to 720 hours without an idle timeout in password mode", () => {
    const result = load({ AUTH_MODE: "password" });
    expect(result.ok).toBe(true);
    expect(result.ok && result.config.session).toEqual({ maxAgeMs: 720 * HOUR, idleTimeoutMs: null });
  });

  it("defaults to 24 hours without an idle timeout in oidc mode", () => {
    const result = loadOidc({});
    expect(result.ok).toBe(true);
    expect(result.ok && result.config.session).toEqual({ maxAgeMs: 24 * HOUR, idleTimeoutMs: null });
  });

  it("treats empty strings as unset", () => {
    const result = loadOidc({ SESSION_MAX_AGE_HOURS: "", SESSION_IDLE_TIMEOUT_HOURS: "" });
    expect(result.ok).toBe(true);
    expect(result.ok && result.config.session).toEqual({ maxAgeMs: 24 * HOUR, idleTimeoutMs: null });
  });

  it.each([
    ["1", 1],
    ["168", 168],
    ["9600", 9600],
  ])("accepts %j hours in both variables", (value, hours) => {
    const result = loadOidc({ SESSION_MAX_AGE_HOURS: value, SESSION_IDLE_TIMEOUT_HOURS: value });
    expect(result.ok).toBe(true);
    expect(result.ok && result.config.session).toEqual({ maxAgeMs: hours * HOUR, idleTimeoutMs: hours * HOUR });
  });

  it("uses both variables in password mode", () => {
    const result = load({ AUTH_MODE: "password", SESSION_MAX_AGE_HOURS: "2160", SESSION_IDLE_TIMEOUT_HOURS: "168" });
    expect(result.ok).toBe(true);
    expect(result.ok && result.config.session).toEqual({ maxAgeMs: 2160 * HOUR, idleTimeoutMs: 168 * HOUR });
  });

  it("accepts an idle timeout longer than the max age", () => {
    const result = load({ SESSION_MAX_AGE_HOURS: "24", SESSION_IDLE_TIMEOUT_HOURS: "48" });
    expect(result.ok).toBe(true);
    expect(result.ok && result.config.session).toEqual({ maxAgeMs: 24 * HOUR, idleTimeoutMs: 48 * HOUR });
  });

  const invalidValues: [unknown][] = [
    ["0"],
    ["-1"],
    ["1.5"],
    ["24h"],
    [" 24"],
    ["24 "],
    ["01"],
    ["9601"],
    ["99999999999999999999"],
    [168],
    [true],
  ];

  it.each(invalidValues)("rejects SESSION_MAX_AGE_HOURS=%j", (value) => {
    const result = load({ SESSION_MAX_AGE_HOURS: value as string });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.invalid).toContain("SESSION_MAX_AGE_HOURS");
  });

  it.each(invalidValues)("rejects SESSION_IDLE_TIMEOUT_HOURS=%j", (value) => {
    const result = load({ SESSION_IDLE_TIMEOUT_HOURS: value as string });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.invalid).toContain("SESSION_IDLE_TIMEOUT_HOURS");
  });

  it("rejects invalid values in oidc mode", () => {
    const result = loadOidc({ SESSION_MAX_AGE_HOURS: "0", SESSION_IDLE_TIMEOUT_HOURS: "x" });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.invalid).toEqual(
      expect.arrayContaining(["SESSION_MAX_AGE_HOURS", "SESSION_IDLE_TIMEOUT_HOURS"]),
    );
  });
});

describe("loadConfig INITIAL_ADMIN_EMAIL", () => {
  const loadOidc = (overrides: Partial<CoreBindings>) =>
    loadConfig({ ...workerEnv, ...oidcEnv, ...overrides } as CoreBindings);

  it.each([
    [undefined, null],
    ["", null],
    ["admin@example.com", "admin@example.com"],
    [" Admin@Example.COM ", "admin@example.com"],
  ])("reads %j as %j in oidc mode", (value, expected) => {
    const result = loadOidc({ INITIAL_ADMIN_EMAIL: value });
    expect(result.ok).toBe(true);
    expect(result.ok && result.config.oidc?.initialAdminEmail).toBe(expected);
  });

  it.each([["not-an-email"], [" "], [1 as unknown as string], [true as unknown as string]])(
    "rejects %j in oidc mode",
    (value) => {
      const result = loadOidc({ INITIAL_ADMIN_EMAIL: value });
      expect(result.ok).toBe(false);
      expect(!result.ok && result.invalid).toContain("INITIAL_ADMIN_EMAIL");
    },
  );

  it("ignores the value in password mode", () => {
    const result = loadConfig({ ...workerEnv, AUTH_MODE: "password", INITIAL_ADMIN_EMAIL: "bogus" } as CoreBindings);
    expect(result.ok).toBe(true);
    expect(result.ok && result.config.oidc).toBeNull();
  });

  it("ignores ALLOWED_EMAILS left in the environment", () => {
    for (const value of ["", "*", "example.com", 1]) {
      const leftover: Record<string, unknown> = { ALLOWED_EMAILS: value };
      const result = loadConfig({ ...workerEnv, ...oidcEnv, ...leftover } as CoreBindings);
      expect(result.ok).toBe(true);
      expect(result.ok && Object.keys(result.config.oidc ?? {})).not.toContain("allowedEmails");
    }
  });
});

describe("loadConfig OIDC_ISSUER", () => {
  const loadOidc = (issuer: string) =>
    loadConfig({ ...workerEnv, ...oidcEnv, OIDC_ISSUER: issuer } as CoreBindings);

  it.each(["https://idp.example.com", "https://idp.example.com/realms/x"])("accepts the issuer %s as is", (issuer) => {
    const result = loadOidc(issuer);
    expect(result.ok && result.config.oidc?.issuer).toBe(issuer);
  });

  it.each([
    "https://idp.example.com/.well-known/openid-configuration",
    "https://idp.example.com/realms/x/.well-known/openid-configuration",
    "http://idp.example.com",
  ])("rejects %s", (issuer) => {
    const result = loadOidc(issuer);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.invalid).toContain("OIDC_ISSUER");
  });
});
