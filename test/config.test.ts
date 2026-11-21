import { describe, expect, it } from "vitest";
import { env as workerEnv } from "cloudflare:workers";
import { loadConfig, type CoreBindings } from "../src/config.js";
import { oidcEnv } from "./helpers.js";

const HOUR = 60 * 60 * 1000;

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
