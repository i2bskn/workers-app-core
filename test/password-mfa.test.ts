import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { env as workerEnv } from "cloudflare:workers";
import { hashRecoveryCode } from "../src/auth/mfa-factors.js";
import { hooks } from "./fixture/src/index.js";
import { clock } from "../src/clock.js";
import { createTestAuthenticator } from "./fixture/webauthn.js";
import { AT, RT, ORIGIN, PASSWORD, countTable, createUser, login, resetDb, send, sessionCookies, setCookies } from "./helpers.js";

const key = btoa("k".repeat(32));
const optional = { PASSWORD_MFA_KEY: key, APP_ORIGIN: ORIGIN };
const required = { ...optional, PASSWORD_MFA_POLICY: "all" };
const email = "admin@example.com";
const pendingCookie = "__Host-testapp_mfa";

beforeEach(resetDb);
afterEach(() => { vi.restoreAllMocks(); });

function pendingCookies(response: Response) {
  const cookies = setCookies(response);
  expect(cookies[AT]).toBeUndefined();
  expect(cookies[RT]).toBeUndefined();
  const pending = cookies[pendingCookie];
  expect(pending?.raw).toContain("HttpOnly");
  if (!pending) throw new Error("MFA pending cookie missing");
  return { [pendingCookie]: pending.value };
}

// A separate authenticator, using the base32 setup key shown to the user.
async function authenticatorCode(secret: string, now: number) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = Array.from(secret, c => alphabet.indexOf(c).toString(2).padStart(5, "0")).join("");
  const keyBytes = Uint8Array.from(bits.match(/.{8}/g)!, byte => parseInt(byte, 2));
  const hmac = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = new ArrayBuffer(8);
  new DataView(counter).setBigUint64(0, BigInt(Math.floor(now / 30000)));
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmac, counter));
  const offset = mac[19]! & 15;
  return String((new DataView(mac.buffer).getUint32(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
}

describe("password MFA through the Worker", () => {
  it("registers a passkey voluntarily and requires its signature on the next password login", async () => {
    await createUser({ email });
    const authenticator = await createTestAuthenticator(ORIGIN);
    const loginForm = { email, password: PASSWORD, next: "/wiki" };
    const enrollment = pendingCookies(await send("/auth/login", { env: optional, form: { ...loginForm, mfa: "enroll" } }));
    const options = async (cookies: Record<string, string>) => {
      const response = await send("/auth/mfa/webauthn/options", { env: optional, cookies, json: {} });
      expect(response.status).toBe(200);
      return response.json<{ challenge: string }>();
    };
    const registration = await authenticator.register((await options(enrollment)).challenge);
    const confirmed = await send("/auth/mfa/webauthn/verify", {
      env: optional, cookies: enrollment, form: { response: JSON.stringify(registration) },
    });
    expect(confirmed.status).toBe(200);
    sessionCookies(confirmed);
    const pending = pendingCookies(await send("/auth/login", { env: optional, form: loginForm }));
    const assertion = await authenticator.authenticate((await options(pending)).challenge);
    const verified = await send("/auth/mfa/webauthn/verify", {
      env: optional, cookies: pending, form: { response: JSON.stringify(assertion) },
    });
    expect(verified.status).toBe(303);
    expect(verified.headers.get("Location")).toBe("/wiki");
    sessionCookies(verified);

    const disable = { ...loginForm, mfa: "disable" };
    expect((await send("/auth/login", { env: required, form: disable })).status).toBe(403);
    const removal = pendingCookies(await send("/auth/login", { env: optional, form: disable }));
    const confirmation = await authenticator.authenticate((await options(removal)).challenge);
    const disabled = await send("/auth/mfa/webauthn/verify", {
      env: optional, cookies: removal, form: { response: JSON.stringify(confirmation) },
    });
    expect(disabled.status).toBe(200);
    sessionCookies(await send("/auth/login", { env: optional, form: loginForm }));
  });

  it("limits first-admin setup to enrollment, then verifies TOTP or a single-use recovery code", async () => {
    let now = Date.now();
    vi.spyOn(clock, "now").mockImplementation(() => now);
    const setup = await send("/auth/setup", { env: required, form: { email, name: "Admin", password: PASSWORD, password_confirm: PASSWORD } });
    expect(setup.status).toBe(303);
    const pending = pendingCookies(setup);
    expect((await send("/api/v1/me", { env: required, cookies: pending })).status).toBe(401);
    const start = await send("/auth/mfa/totp/start", { method: "POST", env: required, cookies: pending });
    const enrollmentHtml = await start.text();
    const secret = /<code>([A-Z2-7]+)<\/code>/.exec(enrollmentHtml)?.[1];
    if (!secret) throw new Error("TOTP setup key missing");
    const form = { code: await authenticatorCode(secret, now) };
    const enrolled = await send("/auth/mfa/totp", { env: required, cookies: pending, form });
    expect(enrolled.status).toBe(200);
    expect((await send("/api/v1/me", { env: required, cookies: sessionCookies(enrolled) })).status).toBe(200);
    const recovery = /<li><code>([A-Z2-7-]+)<\/code>/.exec(await enrolled.text())?.[1];
    if (!recovery) throw new Error("Recovery codes missing");

    // Enrolled users also verify MFA under the optional policy.
    const login = async () => pendingCookies(await send("/auth/login", { env: optional, form: { email, password: PASSWORD, next: "/authorize?state=example" } }));
    const challenge = await login();
    now += 30000;
    const verified = await send("/auth/mfa/totp", { env: optional, cookies: challenge, form: { code: await authenticatorCode(secret, now) } });
    expect(verified.status).toBe(303);
    expect(verified.headers.get("Location")).toBe("/authorize?state=example");
    sessionCookies(verified);
    const another = await login();
    const repeated = await send("/auth/mfa/totp", { env: optional, cookies: another, form: { code: await authenticatorCode(secret, now) } });
    expect(repeated.status).toBe(400);
    expectNoSession(repeated);
    const restored = await send("/auth/mfa/recovery", { env: optional, cookies: another, form: { code: recovery } });
    expect(restored.status).toBe(303);
    sessionCookies(restored);
    const used = await send("/auth/mfa/recovery", { env: optional, cookies: await login(), form: { code: recovery } });
    expect(used.status).toBe(400);
    expectNoSession(used);
  });

  it("only requires administrator enrollment under the admins policy", async () => {
    const env = { ...optional, PASSWORD_MFA_POLICY: "admins" };
    const admin = await createUser({ email, role: "admin" });
    const member = await createUser({ email: "member@example.com" });
    sessionCookies(await send("/auth/login", { env, form: { email: member.email, password: PASSWORD } }));
    const start = await send("/auth/login", { env, form: { email: admin.email, password: PASSWORD } });
    const cookies = pendingCookies(start);
    expect((await send("/api/v1/me", { env, cookies })).status).toBe(401);
  });

  it("requires same-origin requests for MFA", async () => {
    await createUser({ email });
    const env = required;
    const cookies = await begin();
    const crossOrigin = await send("/auth/mfa/totp/start", { method: "POST", origin: "https://another.test", env, cookies });
    expect(crossOrigin.status).toBe(403);
  });

  it("accepts WebAuthn ceremonies only at the configured origin, including requests that pass CSRF checks", async () => {
    await createUser({ email });
    const cookies = await begin();
    const challenge = await webauthnChallenge(cookies);
    const authenticator = await createTestAuthenticator(ORIGIN);
    const response = JSON.stringify(await authenticator.register(challenge));
    const alias = "https://alias.test";
    const wrongOptions = await send(alias + "/auth/mfa/webauthn/options", { env: required, cookies, json: {} });
    expect(wrongOptions.status).toBe(400);
    const wrongVerify = await send(alias + "/auth/mfa/webauthn/verify", { env: required, cookies, form: { response } });
    expect(wrongVerify.status).toBe(400);
    expectNoSession(wrongVerify);
    expect(await workerEnv.DB.prepare("SELECT challenge, attempts FROM mfa_pending").first()).toEqual({ challenge, attempts: 0 });
    expect(await countTable("sessions")).toBe(0);
    expect(await countTable("mfa_credentials")).toBe(0);

    const accepted = await send("/auth/mfa/webauthn/verify", { env: required, cookies, form: { response } });
    expect(accepted.status).toBe(200);
    sessionCookies(accepted);
  });

  it("preserves enrolled factors across an administrator password reset", async () => {
    const admin = await createUser({ email, role: "admin" });
    const adminCookies = await login(admin.email);
    const member = await createUser({ email: "member@example.com" });
    const begin = async (password: string, mfa = "") =>
      pendingCookies(await send("/auth/login", { env: optional, form: { email: member.email, password, mfa } }));
    const enrollment = await begin(PASSWORD, "enroll");
    const start = await send("/auth/mfa/totp/start", { method: "POST", env: optional, cookies: enrollment });
    const secret = /<code>([A-Z2-7]+)<\/code>/.exec(await start.text())?.[1];
    if (!secret) throw new Error("TOTP setup key missing");
    const confirmed = await send("/auth/mfa/totp", {
      env: optional, cookies: enrollment, form: { code: await authenticatorCode(secret, Date.now()) },
    });
    const recovery = /<li><code>([A-Z2-7-]+)<\/code>/.exec(await confirmed.text())?.[1];
    if (!recovery) throw new Error("Recovery codes missing");
    const pendingBeforeReset = await begin(PASSWORD);
    const newPassword = "another test passphrase";
    const changed = await send(`/api/v1/users/${member.id}/password`, { env: optional, cookies: adminCookies, json: { password: newPassword } });
    expect(changed.status).toBe(204);
    const stale = await send("/auth/mfa/recovery", { env: optional, cookies: pendingBeforeReset, form: { code: recovery } });
    expect(stale.status).toBe(401);
    const fresh = await send("/auth/mfa/recovery", { env: optional, cookies: await begin(newPassword), form: { code: recovery } });
    expect(fresh.status).toBe(303);
    sessionCookies(fresh);
  });
});

const loginForm = { email, password: PASSWORD, next: "/wiki" };

async function begin(mfa = "") {
  return pendingCookies(await send("/auth/login", { env: required, form: { ...loginForm, mfa } }));
}

function setupKey(html: string) {
  const secret = /<code>([A-Z2-7]+)<\/code>/.exec(html)?.[1];
  if (!secret) throw new Error("TOTP setup key missing");
  return secret;
}

async function startTotp(cookies: Record<string, string>) {
  const res = await send("/auth/mfa/totp/start", { method: "POST", env: required, cookies });
  expect(res.status).toBe(200);
  return setupKey(await res.text());
}

async function webauthnChallenge(cookies: Record<string, string>) {
  const res = await send("/auth/mfa/webauthn/options", { env: required, cookies, json: {} });
  expect(res.status).toBe(200);
  return (await res.json<{ challenge: string }>()).challenge;
}

async function newPasskeyResponse(cookies: Record<string, string>) {
  const authenticator = await createTestAuthenticator(ORIGIN);
  return JSON.stringify(await authenticator.register(await webauthnChallenge(cookies)));
}

function codesFrom(html: string) {
  const codes = Array.from(html.matchAll(/<li><code>([A-Z2-7-]+)<\/code><\/li>/g), match => match[1]!);
  expect(codes).toHaveLength(8);
  return codes;
}

async function enrolledMember() {
  const user = await createUser({ email });
  const cookies = await begin();
  const secret = await startTotp(cookies);
  const code = await authenticatorCode(secret, clock.now());
  const res = await send("/auth/mfa/totp", { env: required, cookies, form: { code } });
  sessionCookies(res);
  return { user, secret, code, codes: codesFrom(await res.text()) };
}

function recover(cookies: Record<string, string>, code: string, mfa = "") {
  return send("/auth/mfa/recovery", { env: required, cookies, form: { code, mfa } });
}

function expectNoSession(res: Response) {
  expect(setCookies(res)[AT]).toBeUndefined();
  expect(setCookies(res)[RT]).toBeUndefined();
}

describe("WebAuthn assertion verification through the Worker", () => {
  let authenticator: Awaited<ReturnType<typeof createTestAuthenticator>>;

  function verify(cookies: Record<string, string>, response: string) {
    return send("/auth/mfa/webauthn/verify", { env: required, cookies, form: { response } });
  }

  beforeEach(async () => {
    await createUser({ email });
    const enrollment = await begin();
    // A counterless passkey isolates the challenge check from signature-counter replay protection.
    authenticator = await createTestAuthenticator(ORIGIN, { supportsCounter: false });
    const registration = await authenticator.register(await webauthnChallenge(enrollment));
    const result = await verify(enrollment, JSON.stringify(registration));
    expect(result.status).toBe(200);
    sessionCookies(result);
  });

  it("rejects an accepted assertion in a new sign-in with a different challenge", async () => {
    const first = await begin();
    const challenge = await webauthnChallenge(first);
    const assertion = JSON.stringify(await authenticator.authenticate(challenge));
    const success = await verify(first, assertion);
    expect(success.status).toBe(303);
    sessionCookies(success);

    const next = await begin();
    expect(await webauthnChallenge(next)).not.toBe(challenge);
    const before = await countTable("sessions");
    const rejected = await verify(next, assertion);
    expect(rejected.status).toBe(400);
    expectNoSession(rejected);
    expect(await countTable("sessions")).toBe(before);
  });

  it("rejects verification before issuing options without charging an attempt", async () => {
    const first = await begin();
    const assertion = JSON.stringify(await authenticator.authenticate(await webauthnChallenge(first)));
    const success = await verify(first, assertion);
    expect(success.status).toBe(303);
    sessionCookies(success);

    const next = await begin();
    const before = await countTable("sessions");
    const rejected = await verify(next, assertion);
    expect(rejected.status).toBe(400);
    expectNoSession(rejected);
    expect(await countTable("sessions")).toBe(before);
    const pending = await workerEnv.DB.prepare("SELECT attempts, challenge FROM mfa_pending").first();
    expect(pending).toEqual({ attempts: 0, challenge: null });
  });

  it.each([
    [65536, 303],
    [65537, 400],
  ])("verifies a %i-character signed response with status %i", async (length, status) => {
    const pending = await begin();
    const assertion = await authenticator.authenticate(await webauthnChallenge(pending));
    // JSON whitespace changes the form field length without changing any signed data.
    const response = JSON.stringify(assertion).padEnd(length, " ");
    expect(response).toHaveLength(length);
    const before = await countTable("sessions");
    const result = await verify(pending, response);
    expect(result.status).toBe(status);
    if (status === 303) {
      sessionCookies(result);
      expect(await countTable("sessions")).toBe(before + 1);
    } else {
      expectNoSession(result);
      expect(await countTable("sessions")).toBe(before);
    }
  });

  it("rejects malformed JSON after issuing a challenge", async () => {
    const pending = await begin();
    await webauthnChallenge(pending);
    const before = await countTable("sessions");
    const rejected = await verify(pending, "{");
    expect(rejected.status).toBe(400);
    expectNoSession(rejected);
    expect(await countTable("sessions")).toBe(before);
  });
});

describe("MFA session issuance", () => {
  it("checks the user's current role when issuing a password-only session", async () => {
    const { id } = await createUser({ email, role: "member" });
    hooks.beforeSessionIssued = async () => {
      await workerEnv.DB.prepare("UPDATE users SET role = 'admin' WHERE id = ?").bind(id).run();
    };
    const res = await send("/auth/login", { env: { ...optional, PASSWORD_MFA_POLICY: "admins" }, form: loginForm });
    expect(res.status).toBe(401);
    expectNoSession(res);
    expect(await countTable("sessions")).toBe(0);
    expect(await workerEnv.DB.prepare("SELECT role FROM users WHERE id = ?").bind(id).first("role")).toBe("admin");
  });

  it("refuses a password-only session when the administrator resets the password during the hook", async () => {
    const owner = await createUser({ email: "owner@example.com", role: "admin" });
    const adminCookies = await login(owner.email);
    const member = await createUser({ email });
    const before = await countTable("sessions");
    hooks.beforeSessionIssued = async () => {
      const reset = await send(`/api/v1/users/${member.id}/password`, {
        env: optional, cookies: adminCookies, json: { password: "a different passphrase" },
      });
      expect(reset.status).toBe(204);
    };
    const res = await send("/auth/login", { env: optional, form: loginForm });
    expect(res.status).toBe(401);
    expectNoSession(res);
    expect(await countTable("sessions")).toBe(before);
  });

  it("refuses a password-only session when another sign-in completes MFA enrollment during the hook", async () => {
    await createUser({ email });
    const enrolling = await begin("enroll");
    const secret = await startTotp(enrolling);
    hooks.beforeSessionIssued = async () => {
      delete hooks.beforeSessionIssued;
      const registered = await send("/auth/mfa/totp", {
        env: optional, cookies: enrolling, form: { code: await authenticatorCode(secret, clock.now()) },
      });
      expect(registered.status).toBe(200);
      sessionCookies(registered);
    };
    const res = await send("/auth/login", { env: optional, form: loginForm });
    expect(res.status).toBe(401);
    expectNoSession(res);
    expect(await countTable("sessions")).toBe(1); // The concurrent enrollment issued this session.
  });

  it("rechecks the password after the session hook and preserves an unused recovery code on reset", async () => {
    const admin = await createUser({ email: "owner@example.com", role: "admin" });
    const adminCookies = await login(admin.email);
    const { user, codes } = await enrolledMember();
    const pending = await begin();
    const before = await countTable("sessions");
    hooks.beforeSessionIssued = async () => {
      const reset = await send(`/api/v1/users/${user.id}/password`, {
        env: required, cookies: adminCookies, json: { password: "changed passphrase" },
      });
      expect(reset.status).toBe(204);
    };
    expectNoSession(await recover(pending, codes[0]!));
    expect(await countTable("sessions")).toBe(before);
    expect(await countTable("mfa_recovery_codes")).toBe(8);
    delete hooks.beforeSessionIssued;
    const retry = pendingCookies(await send("/auth/login", {
      env: required, form: { email, password: "changed passphrase" },
    }));
    sessionCookies(await recover(retry, codes[0]!));
  });

  it("checks expiry again when the hook returns", async () => {
    let now = Date.now();
    vi.spyOn(clock, "now").mockImplementation(() => now);
    const { codes } = await enrolledMember();
    const cookies = await begin();
    hooks.beforeSessionIssued = async () => { now += 300_001; };
    expectNoSession(await recover(cookies, codes[0]!));
    expect(await countTable("sessions")).toBe(1);
    expect(await countTable("mfa_recovery_codes")).toBe(8);
  });

  it("runs the session hook only for valid, unused proofs and leaves the recovery code usable if it throws", async () => {
    const { codes, code } = await enrolledMember();
    const cookies = await begin();
    const hook = vi.fn(async () => { throw new Error("fixture session hook failed"); });
    hooks.beforeSessionIssued = hook;
    const wrong = await recover(cookies, "INVALID");
    expect(wrong.status).toBe(400);
    const replay = await send("/auth/mfa/totp", { env: required, cookies, form: { code } });
    expect(replay.status).toBe(400);
    expect(hook).not.toHaveBeenCalled();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const failed = await recover(cookies, codes[0]!);
    expect(failed.status).toBe(500);
    expectNoSession(failed);
    expect(hook).toHaveBeenCalledTimes(1);
    expect(await countTable("mfa_recovery_codes")).toBe(8);
    delete hooks.beforeSessionIssued;
    sessionCookies(await recover(cookies, codes[0]!));
  });

  it.each(["hook", "session insert"])("preserves the original factors and codes if %s fails during replacement", async failure => {
    const { codes } = await enrolledMember();
    const cookies = await begin("replace");
    const verified = await recover(cookies, codes[0]!);
    expect(verified.status).toBe(303);
    const secret = await startTotp(cookies);
    const form = { code: await authenticatorCode(secret, clock.now()) };
    const originalHashes = await workerEnv.DB.prepare("SELECT hash FROM mfa_recovery_codes ORDER BY hash").all();
    vi.spyOn(console, "error").mockImplementation(() => {});
    if (failure === "hook") {
      hooks.beforeSessionIssued = async () => { throw new Error("fixture hook failed"); };
    } else {
      await workerEnv.DB.prepare("CREATE TRIGGER fail_mfa_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'fixture failure'); END").run();
    }
    try {
      const failed = await send("/auth/mfa/totp", { env: required, cookies, form });
      expect(failed.status).toBe(500);
      expectNoSession(failed);
      expect(await countTable("sessions")).toBe(1);
      expect(await workerEnv.DB.prepare("SELECT revision FROM mfa_accounts").first("revision")).toBe(1);
      const hashes = await workerEnv.DB.prepare("SELECT hash FROM mfa_recovery_codes ORDER BY hash").all();
      expect(hashes.results).toEqual(originalHashes.results);
      expect(hashes.results).toHaveLength(8);
    } finally {
      if (failure === "session insert") await workerEnv.DB.prepare("DROP TRIGGER fail_mfa_session").run();
      delete hooks.beforeSessionIssued;
    }
    const retry = await send("/auth/mfa/totp", { env: required, cookies, form });
    sessionCookies(retry);
    expect(codesFrom(await retry.text())).not.toEqual(codes);
  });
});

describe("MFA enrollment and recovery", () => {
  it("keeps first-admin setup available when the enrollment method cannot run on the requested host", async () => {
    const env = { APP_ORIGIN: ORIGIN, PASSWORD_MFA_POLICY: "admins" };
    const form = { email, password: PASSWORD, password_confirm: PASSWORD, name: "Owner" };
    const res = await send("https://other.test/auth/setup", { env, form });
    expect(res.status).toBe(503);
    expect(await countTable("users")).toBe(0);
    expect(await countTable("sessions")).toBe(0);
    pendingCookies(await send("/auth/setup", { env, form }));
    expect(await countTable("users")).toBe(1);
  });

  it("returns 503 on login before creating a pending flow if a required method cannot be enrolled at this host", async () => {
    await createUser({ email });
    const env = { APP_ORIGIN: ORIGIN, PASSWORD_MFA_POLICY: "all" };
    const res = await send("https://alias.test/auth/login", { env, form: loginForm });
    expect(res.status).toBe(503);
    expectNoSession(res);
    expect(setCookies(res)[pendingCookie]).toBeUndefined();
    expect(await countTable("mfa_pending")).toBe(0);
    expect(await countTable("sessions")).toBe(0);
    pendingCookies(await send("/auth/login", { env, form: loginForm }));
  });

  it("excludes the current credential from replacement options and keeps it usable until replacement completes", async () => {
    await createUser({ email });
    const authenticator = await createTestAuthenticator(ORIGIN);
    const enrollment = await begin();
    const credential = await authenticator.register(await webauthnChallenge(enrollment));
    const registered = await send("/auth/mfa/webauthn/verify", {
      env: required, cookies: enrollment, form: { response: JSON.stringify(credential) },
    });
    expect(registered.status).toBe(200);
    const [code] = codesFrom(await registered.text());

    const replacing = await begin("replace");
    const confirmed = await recover(replacing, code!);
    expect(confirmed.status).toBe(303);
    expect(confirmed.headers.get("Location")).toBe("/auth/mfa");
    const options = await send("/auth/mfa/webauthn/options", { env: required, cookies: replacing, json: {} });
    expect(options.status).toBe(200);
    const { excludeCredentials } = await options.json<{ excludeCredentials: { id: string }[] }>();
    expect(excludeCredentials.map(key => key.id)).toEqual([credential.id]);

    const fresh = await begin();
    const assertion = await authenticator.authenticate(await webauthnChallenge(fresh));
    const login = await send("/auth/mfa/webauthn/verify", {
      env: required, cookies: fresh, form: { response: JSON.stringify(assertion) },
    });
    expect(login.status).toBe(303);
    sessionCookies(login);
  });

  it("returns to the requested page and preserves recovery codes when an enrolled TOTP authorizes adding a passkey", async () => {
    const { secret, codes } = await enrolledMember();
    const cookies = await begin("enroll");
    const verified = await send("/auth/mfa/totp", {
      env: required, cookies, form: { code: await authenticatorCode(secret, clock.now() + 30_000) },
    });
    expect(verified.status).toBe(303);
    expect(verified.headers.get("Location")).toBe("/auth/mfa");
    expectNoSession(verified);
    const response = await newPasskeyResponse(cookies);
    const added = await send("/auth/mfa/webauthn/verify", { env: required, cookies, form: { response } });
    expect(added.status).toBe(303);
    expect(added.headers.get("Location")).toBe("/wiki");
    sessionCookies(added);
    expect(await countTable("mfa_credentials")).toBe(1);
    const stored = await workerEnv.DB.prepare("SELECT hash FROM mfa_recovery_codes ORDER BY hash").all<{ hash: string }>();
    expect(stored.results.map(row => row.hash)).toEqual((await Promise.all(codes.map(hashRecoveryCode))).sort());
  });

  it("keeps the same TOTP setup key on retry, reload and repeated starts", async () => {
    await createUser({ email });
    const cookies = await begin();
    const [secret, simultaneous] = await Promise.all([startTotp(cookies), startTotp(cookies)]);
    expect(simultaneous).toBe(secret);
    const wrong = await send("/auth/mfa/totp", { env: required, cookies, form: { code: "invalid" } });
    expect(wrong.status).toBe(400);
    const page = await send("/auth/mfa", { env: required, cookies });
    expect(setupKey(await page.text())).toBe(secret);
    expect(await startTotp(cookies)).toBe(secret);
    sessionCookies(await send("/auth/mfa/totp", { env: required, cookies, form: { code: await authenticatorCode(secret, clock.now()) } }));
  });

  it("cancels an enrollment when its pending browser logs out", async () => {
    await createUser({ email });
    const cookies = await begin();
    const res = await send("/auth/logout", { env: required, method: "POST", cookies });
    expect(res.ok).toBe(true);
    expect(setCookies(res)[pendingCookie]?.value).toBe("");
    expect((await send("/auth/mfa", { env: required, cookies })).status).toBe(401);
    expect(await countTable("mfa_pending")).toBe(0);
  });

  it("declines disabling an account with no enrolled factor", async () => {
    await createUser({ email });
    const res = await send("/auth/login", { env: optional, form: { ...loginForm, mfa: "disable" } });
    expect(res.status).toBe(400);
    expectNoSession(res);
    expect(await countTable("mfa_pending")).toBe(0);
  });

  it("declines adding an unavailable factor before asking for a recovery code", async () => {
    await enrolledMember();
    const res = await send("/auth/login", { env: { PASSWORD_MFA_KEY: key }, form: { ...loginForm, mfa: "enroll" } });
    expect(res.status).toBe(400);
    expect(await countTable("mfa_pending")).toBe(0);
    expect(await countTable("mfa_recovery_codes")).toBe(8);
  });

  it("preserves the last of two concurrently submitted codes and can resume a lost-device replacement", async () => {
    const { secret, codes } = await enrolledMember();
    const remaining = codes.slice(0, 2);
    const hashes = await Promise.all(remaining.map(hashRecoveryCode));
    await workerEnv.DB.prepare("DELETE FROM mfa_recovery_codes WHERE hash NOT IN (?, ?)").bind(...hashes).run();
    const [one, two] = await Promise.all([begin(), begin()]);
    const responses = await Promise.all([recover(one, remaining[0]!), recover(two, remaining[1]!)]);
    expect(responses.map(r => r.headers.get("Location")).sort()).toEqual(["/auth/mfa", "/wiki"]);
    const idx = responses.findIndex(r => r.headers.get("Location") === "/auth/mfa");
    expectNoSession(responses[idx]!);
    sessionCookies(responses[1 - idx]!);
    expect(await countTable("mfa_recovery_codes")).toBe(1);

    // The original replacement can be abandoned without spending the user's last code.
    const retry = await begin();
    expect((await recover(retry, remaining[idx]!)).headers.get("Location")).toBe("/auth/mfa");
    const response = await newPasskeyResponse(retry);
    const enrolled = await send("/auth/mfa/webauthn/verify", { env: required, cookies: retry, form: { response } });
    sessionCookies(enrolled);
    const renewed = codesFrom(await enrolled.text());
    expect(renewed.some(c => codes.includes(c))).toBe(false);
    expect((await send("/auth/mfa", { env: required, cookies: idx === 0 ? one : two })).status).toBe(401);
    const login = await begin();
    const old = await send("/auth/mfa/totp", {
      env: required, cookies: login, form: { code: await authenticatorCode(secret, clock.now() + 30000) },
    });
    expect(old.status).toBe(400);
    sessionCookies(await recover(login, renewed[0]!));
  });

  it("requires the recovery code to remain unused until a factor addition commits", async () => {
    const { codes } = await enrolledMember();
    const cookies = await begin("enroll");
    expect((await recover(cookies, codes[0]!)).headers.get("Location")).toBe("/auth/mfa");
    expect(await countTable("mfa_recovery_codes")).toBe(8);
    const response = await newPasskeyResponse(cookies);
    sessionCookies(await recover(await begin(), codes[0]!));
    const hook = vi.fn(async () => {});
    hooks.beforeSessionIssued = hook;
    const stale = await send("/auth/mfa/webauthn/verify", { env: required, cookies, form: { response } });
    expect(stale.status).toBe(400);
    expectNoSession(stale);
    expect(hook).not.toHaveBeenCalled();
    expect(await countTable("mfa_credentials")).toBe(0);
  });

  it("keeps the existing TOTP and delivers new recovery codes when the last code authorizes adding a passkey", async () => {
    const { codes, secret } = await enrolledMember();
    await workerEnv.DB.prepare("DELETE FROM mfa_recovery_codes WHERE hash <> ?").bind(await hashRecoveryCode(codes[0]!)).run();
    const cookies = await begin("enroll");
    expect((await recover(cookies, codes[0]!)).headers.get("Location")).toBe("/auth/mfa");
    const response = await newPasskeyResponse(cookies);
    const added = await send("/auth/mfa/webauthn/verify", { env: required, cookies, form: { response } });
    sessionCookies(added);
    expect(codesFrom(await added.text())).not.toContain(codes[0]);
    expect(await countTable("mfa_credentials")).toBe(1);
    const next = await begin();
    expect((await recover(next, codes[0]!)).status).toBe(400);
    sessionCookies(await send("/auth/mfa/totp", {
      env: required, cookies: next, form: { code: await authenticatorCode(secret, clock.now() + 30000) },
    }));
  });

  it("replaces a locked TOTP device using the last recovery code on a TOTP-only deployment", async () => {
    const { codes, secret: oldSecret } = await enrolledMember();
    const onlyTotp = { PASSWORD_MFA_KEY: key, PASSWORD_MFA_POLICY: "all" };
    await workerEnv.DB.prepare("DELETE FROM mfa_recovery_codes WHERE hash <> ?").bind(await hashRecoveryCode(codes[0]!)).run();
    await workerEnv.DB.prepare("UPDATE mfa_accounts SET totp_attempts = 20, totp_retry_at = ?").bind(clock.now() + 86_400_000).run();
    const cookies = pendingCookies(await send("/auth/login", { env: onlyTotp, form: loginForm }));
    const blocked = await send("/auth/mfa/totp", {
      env: onlyTotp, cookies, form: { code: await authenticatorCode(oldSecret, clock.now() + 30000) },
    });
    expect(blocked.status).toBe(429);
    const recovery = await send("/auth/mfa/recovery", { env: onlyTotp, cookies, form: { code: codes[0]! } });
    expect(recovery.headers.get("Location")).toBe("/auth/mfa");
    const start = await send("/auth/mfa/totp/start", { env: onlyTotp, cookies, method: "POST" });
    const secret = setupKey(await start.text());
    const finish = await send("/auth/mfa/totp", {
      env: onlyTotp, cookies, form: { code: await authenticatorCode(secret, clock.now()) },
    });
    sessionCookies(finish);
    expect(codesFrom(await finish.text())).not.toContain(codes[0]);
    expect(await workerEnv.DB.prepare("SELECT totp_retry_at FROM mfa_accounts").first("totp_retry_at")).toBe(0);
  });

  it("lets a user choose replacement on the ordinary recovery form before the last code", async () => {
    const { codes } = await enrolledMember();
    const cookies = await begin();
    const res = await recover(cookies, codes[0]!, "replace");
    expect(res.headers.get("Location")).toBe("/auth/mfa");
    expectNoSession(res);
    expect(await countTable("mfa_recovery_codes")).toBe(8);
    expect((await startTotp(cookies)).length).toBeGreaterThan(0);
  });
});

describe("MFA request attempt limits", () => {
  it("charges unsuccessful passkey and recovery confirmations only to their pending flow", async () => {
    const { user, secret } = await enrolledMember();
    const now = clock.now();
    await workerEnv.DB.prepare("UPDATE mfa_accounts SET totp_attempts = 4 WHERE user_id = ?")
      .bind(user.id).run();
    const cookies = await begin();
    expect((await recover(cookies, "mistyped")).status).toBe(400);
    await webauthnChallenge(cookies);
    const failed = await send("/auth/mfa/webauthn/verify", { env: required, cookies, form: { response: "{}" } });
    expect(failed.status).toBe(400);
    expect(await workerEnv.DB.prepare("SELECT attempts FROM mfa_pending WHERE user_id = ?").bind(user.id).first("attempts")).toBe(2);
    expect(await workerEnv.DB.prepare("SELECT totp_attempts, totp_retry_at FROM mfa_accounts WHERE user_id = ?").bind(user.id).first())
      .toEqual({ totp_attempts: 4, totp_retry_at: 0 });
    const valid = await send("/auth/mfa/totp", {
      env: required, cookies: await begin(), form: { code: await authenticatorCode(secret, now + 30_000) },
    });
    expect(valid.status).toBe(303);
    sessionCookies(valid);
  });

  it.each(["passkey", "recovery"])("accepts %s in a fresh flow while the account is waiting to retry TOTP", async method => {
    const user = await createUser({ email });
    const enrollment = await begin();
    const authenticator = await createTestAuthenticator(ORIGIN);
    const registration = await authenticator.register(await webauthnChallenge(enrollment));
    const registered = await send("/auth/mfa/webauthn/verify", {
      env: required, cookies: enrollment, form: { response: JSON.stringify(registration) },
    });
    const codes = codesFrom(await registered.text());
    await workerEnv.DB.prepare("UPDATE mfa_accounts SET totp_attempts = 5, totp_retry_at = ? WHERE user_id = ?")
      .bind(clock.now() + 300_000, user.id).run();
    const cookies = await begin();
    const result = method === "recovery"
      ? await recover(cookies, codes[0]!)
      : await send("/auth/mfa/webauthn/verify", {
        env: required, cookies, form: { response: JSON.stringify(await authenticator.authenticate(await webauthnChallenge(cookies))) },
      });
    expect(result.status).toBe(303);
    sessionCookies(result);
  });

  it.each(["totp", "recovery", "webauthn/verify"])("rejects a valid %s submission after exhausting a pending flow", async route => {
    await createUser({ email });
    const enrollment = await begin();
    const authenticator = await createTestAuthenticator(ORIGIN);
    const secret = await startTotp(enrollment);
    let form: Record<string, string>;
    let wrong: Record<string, string>;
    let cookies = enrollment;
    if (route === "totp") {
      form = { code: await authenticatorCode(secret, clock.now()) };
      wrong = { code: "invalid" };
    } else {
      const response = JSON.stringify(await authenticator.register(await webauthnChallenge(enrollment)));
      const registered = await send("/auth/mfa/webauthn/verify", { env: required, cookies: enrollment, form: { response } });
      const codes = codesFrom(await registered.text());
      cookies = await begin();
      if (route === "recovery") {
        form = { code: codes[0]! };
        wrong = { code: "INVALID" };
      } else {
        form = { response: JSON.stringify(await authenticator.authenticate(await webauthnChallenge(cookies))) };
        wrong = { response: "{}" };
      }
    }
    for (let i = 0; i < 5; i++) {
      const failed = await send(`/auth/mfa/${route}`, { env: required, cookies, form: wrong });
      expect(failed.status).toBe(400);
    }
    const limited = await send(`/auth/mfa/${route}`, { env: required, cookies, form });
    expect(limited.status).toBe(429);
    expectNoSession(limited);
  });
});
