import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:workers";
import {
  beginMfa,
  checkMfaVerification,
  finishMfaEnrollment,
  finishMfaVerification,
  getMfaFactors,
  getMfaLoginState,
  readMfa,
  reserveMfaAttempt,
  setMfaChallenge,
  saveMfaTotpSecret,
  type MfaProof,
  type MfaEnrollment,
} from "../src/auth/mfa-store.js";
import { prepareSessionValues } from "../src/auth/sessions.js";
import type { PasswordMfaConfig } from "../src/config.js";
import { createUser, resetDb, testConfig } from "./helpers.js";

beforeEach(resetDb);
const now = 1_800_000_000_000;

async function setupUser() {
  const { id, passwordHash } = await createUser({ email: "employee@example.net" });
  async function begin(purpose: "login" | "enroll" | "manage" | "disable", revision: number, replace = false, time = now) {
    const token = await beginMfa(env.DB, {
      userId: id, passwordHash: passwordHash!, policy: "optional", next: "/", now: time, purpose, revision, replace,
    });
    if (!token) throw new Error("failed to start MFA");
    return token;
  }
  async function verify(token: string, proof: MfaProof, policy?: PasswordMfaConfig["policy"], time = now) {
    const outcome = await checkMfaVerification(env.DB, token, time, proof, policy, false);
    if (!outcome) return false;
    if (outcome === "enroll") return finishMfaVerification(env.DB, token, time, proof, policy, { outcome, replaceOnRecovery: false });
    const session = await prepareSessionValues(id, testConfig(), time);
    return finishMfaVerification(env.DB, token, time, proof, policy, { outcome, replaceOnRecovery: false, session });
  }
  async function enroll(token: string, factor: MfaEnrollment, hashes: string[], replace: boolean) {
    const session = await prepareSessionValues(id, testConfig(), now);
    return finishMfaEnrollment(env.DB, token, now, factor, hashes, replace, session);
  }
  async function enrollTotp(token: string, secret: string, ...recovery: string[]) {
    return enroll(token, { kind: "totp", secret, step: 42 }, recovery, false);
  }
  async function enrolled() {
    const token = await begin("enroll", 0);
    await saveMfaTotpSecret(env.DB, token, now, "encrypted");
    expect(await enrollTotp(token, "encrypted", "recovery-hash", "spare-recovery-hash")).toBe(true);
  }
  return { begin, verify, enroll, enrollTotp, enrolled, id, passwordHash: passwordHash! };
}

describe("password MFA storage", () => {
  it("permits one winning enrollment even when two browsers verified the same initial password", async () => {
    const { begin, enrollTotp, id } = await setupUser();
    const [a, b] = await Promise.all([begin("enroll", 0), begin("enroll", 0)]);
    await saveMfaTotpSecret(env.DB, a, now, "first");
    await saveMfaTotpSecret(env.DB, b, now, "second");
    const results = await Promise.all([enrollTotp(a, "first", "a"), enrollTotp(b, "second", "b")]);
    expect(results.sort()).toEqual([false, true]);
    expect(await getMfaFactors(env.DB, id)).toMatchObject({ revision: 1 });
    expect(await readMfa(env.DB, a, now)).toBeNull();
    expect(await readMfa(env.DB, b, now)).toBeNull();
  });

  it.each<MfaProof>([{ kind: "totp", step: 43 }, { kind: "recovery", hash: "recovery-hash" }])(
    "accepts a given $kind proof only once across two pending logins", async (proof) => {
      const { begin, enrolled, verify } = await setupUser();
      await enrolled();
      const [a, b] = await Promise.all([begin("login", 1), begin("login", 1)]);
      const results = await Promise.all([a, b].map((token) => verify(token, proof)));
      expect(results.sort()).toEqual([false, true]);
    },
  );

  it("only commits a factor or consumes a proof for the prepared session's user", async () => {
    const { begin, enrollTotp, verify, id } = await setupUser();
    const other = await createUser({ email: "different@example.net" });
    const wrongSession = await prepareSessionValues(other.id, testConfig(), now);
    const token = await begin("enroll", 0);
    await saveMfaTotpSecret(env.DB, token, now, "secret");
    const factor = { kind: "totp", secret: "secret", step: 42 } as const;
    expect(await finishMfaEnrollment(env.DB, token, now, factor, ["code"], false, wrongSession)).toBe(false);
    expect((await getMfaLoginState(env.DB, id, "optional"))?.revision).toBe(0);
    expect(await enrollTotp(token, "secret", "code", "spare")).toBe(true);

    const login = await begin("login", 1);
    const proof = { kind: "recovery", hash: "code" } as const;
    expect(await finishMfaVerification(env.DB, login, now, proof, "optional", {
      outcome: "session", replaceOnRecovery: false, session: wrongSession,
    })).toBe(false);
    expect(await verify(login, proof)).toBe(true);
    expect(await env.DB.prepare("SELECT id FROM sessions WHERE user_id = ?").bind(other.id).first()).toBeNull();
  });

  it("keeps existing factors until replacement succeeds and atomically rotates recovery codes", async () => {
    const { begin, enrolled, id, enroll, verify } = await setupUser();
    await enrolled();
    const manage = await begin("manage", 1, true);
    expect(await verify(manage, { kind: "totp", step: 43 })).toBe(true);
    expect(await readMfa(env.DB, manage, now)).toMatchObject({ purpose: "enroll", replace: true });
    const credential = { id: "my-key", publicKey: "public-key", counter: 0 };
    await setMfaChallenge(env.DB, manage, now, "current-challenge");
    expect(await enroll(manage, {
      kind: "webauthn", credential, challenge: "stale-challenge",
    }, ["new-recovery"], true)).toBe(false);
    expect((await getMfaFactors(env.DB, id)).totp).not.toBeNull();
    expect(await enroll(manage, {
      kind: "webauthn", credential, challenge: "current-challenge",
    }, ["new-recovery"], true)).toBe(true);
    expect(await getMfaFactors(env.DB, id)).toMatchObject({
      revision: 2, totp: null, credentials: [credential],
    });
    expect((await env.DB.prepare("SELECT hash FROM mfa_recovery_codes WHERE user_id = ?").bind(id)
      .all<{ hash: string }>()).results).toEqual([{ hash: "new-recovery" }]);
    const auth = await begin("login", 2);
    await setMfaChallenge(env.DB, auth, now, "assertion");
    const assertion = { kind: "webauthn" as const, id: credential.id, counter: 0, challenge: "assertion" };
    expect(await verify(auth, assertion)).toBe(true);
    expect(await verify(auth, assertion)).toBe(false);
  });

  it("advances a security key counter once and removes all MFA data when its owner is deleted", async () => {
    const { begin, id, enroll, verify } = await setupUser();
    const enrollment = await begin("enroll", 0);
    await setMfaChallenge(env.DB, enrollment, now, "register");
    const credential = { id: "hardware-key", publicKey: "key", counter: 3 };
    expect(await enroll(enrollment, {
      kind: "webauthn", credential, challenge: "register",
    }, ["restoration"], false)).toBe(true);

    const tokens = await Promise.all([begin("login", 1), begin("login", 1)]);
    await Promise.all(tokens.map((token) => setMfaChallenge(env.DB, token, now, token)));
    const results = await Promise.all(tokens.map((token) =>
      verify(token, { kind: "webauthn", id: credential.id, counter: 4, challenge: token }),
    ));
    expect(results.sort()).toEqual([false, true]);
    expect((await getMfaFactors(env.DB, id)).credentials[0]?.counter).toBe(4);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id),
      env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id),
    ]);
    for (const table of ["mfa_accounts", "mfa_credentials", "mfa_recovery_codes", "mfa_pending"]) {
      expect(await env.DB.prepare(`SELECT COUNT(*) FROM ${table} WHERE user_id = ?`).bind(id)
        .first<number>("COUNT(*)")).toBe(0);
    }
  });

  it("removes optional MFA with a valid proof, invalidates other pending flows and allows reenrollment", async () => {
    const { id, begin, enrolled, verify } = await setupUser();
    await enrolled();
    const old = await begin("login", 1);
    const disable = await begin("disable", 1);
    expect(await verify(disable, { kind: "totp", step: 43 }, "admins")).toBe(true);
    expect(await readMfa(env.DB, old, now)).toBeNull();
    expect(await readMfa(env.DB, disable, now)).toBeNull();
    expect((await getMfaLoginState(env.DB, id, "optional"))?.revision).toBe(0);
    await enrolled();
    expect((await getMfaLoginState(env.DB, id, "optional"))?.revision).toBe(1);
  });

  it("loads the current role policy and revision together, including before first enrollment", async () => {
    const { id, enrolled, passwordHash } = await setupUser();
    expect(await getMfaLoginState(env.DB, id, "admins")).toEqual({ required: false, revision: 0 });
    expect(await getMfaLoginState(env.DB, id, "all")).toEqual({ required: true, revision: 0 });
    expect(await getMfaLoginState(env.DB, "missing", "optional")).toBeNull();
    await enrolled();
    await env.DB.prepare("UPDATE users SET role = 'admin' WHERE id = ?").bind(id).run();
    expect(await getMfaLoginState(env.DB, id, "admins")).toEqual({ required: true, revision: 1 });
    expect(await getMfaLoginState(env.DB, id, "optional")).toEqual({ required: false, revision: 1 });
    expect(await beginMfa(env.DB, { userId: id, passwordHash, policy: "admins", next: "/", purpose: "disable", revision: 1, now }))
      .toBeNull();
  });

  it("checks the current role and policy before consuming a proof to disable MFA", async () => {
    const { begin, enrolled, id, verify } = await setupUser();
    await enrolled();
    const disable = await begin("disable", 1);
    await env.DB.prepare("UPDATE users SET role = 'admin' WHERE id = ?").bind(id).run();
    const proof = { kind: "recovery" as const, hash: "recovery-hash" };
    for (const policy of [undefined, "all", "admins"] as const) {
      expect(await verify(disable, proof, policy)).toBe(false);
    }
    expect((await getMfaLoginState(env.DB, id, "optional"))?.revision).toBe(1);
    expect(await verify(disable, proof, "optional")).toBe(true);
  });

  it("invalidates pending MFA flows after expiry or password reset", async () => {
    const { begin, enrollTotp, id } = await setupUser();
    const token = await begin("enroll", 0);
    await saveMfaTotpSecret(env.DB, token, now, "encrypted");
    expect(await readMfa(env.DB, token, now + 300_000)).toBeNull();
    await env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind("changed", id).run();
    expect(await readMfa(env.DB, token, now)).toBeNull();
    expect(await enrollTotp(token, "encrypted", "a")).toBe(false);
  });

  it("carries TOTP backoff across fresh flows and clears it on successful verification", async () => {
    const { begin, enrolled, verify } = await setupUser();
    await enrolled();
    let time = now;
    const waits = [0, 5 * 60_000, 30 * 60_000, 4 * 3600_000, 24 * 3600_000];
    for (let attempt = 1; attempt <= 20; attempt++) {
      const token = await begin("login", 1, false, time);
      expect(await reserveMfaAttempt(env.DB, token, time, "totp")).toBe(true);
      const wait = waits[Math.floor(attempt / 5)]!;
      if (wait > 0) {
        const justBefore = time + wait - 1;
        const another = await begin("login", 1, false, justBefore);
        expect(await reserveMfaAttempt(env.DB, another, justBefore, "totp")).toBe(false);
        time = attempt === 20 ? justBefore : justBefore + 1;
      }
    }
    const recovery = await begin("login", 1, false, time);
    expect(await reserveMfaAttempt(env.DB, recovery, time)).toBe(true);
    expect(await verify(recovery, { kind: "recovery", hash: "recovery-hash" }, undefined, time)).toBe(true);
    const next = await begin("login", 1, false, time);
    expect(await reserveMfaAttempt(env.DB, next, time, "totp")).toBe(true);
  });

  it("reserves the last TOTP attempt in parallel only once across flows", async () => {
    const { begin, enrolled } = await setupUser();
    await enrolled();
    const first = await begin("login", 1);
    for (let i = 0; i < 4; i++) expect(await reserveMfaAttempt(env.DB, first, now, "totp")).toBe(true);
    const flows = await Promise.all([begin("login", 1), begin("login", 1)]);
    const results = await Promise.all(flows.map(token => reserveMfaAttempt(env.DB, token, now, "totp")));
    expect(results.sort()).toEqual([false, true]);
  });

  it("charges enrollment and alternative proofs only to their own pending flow", async () => {
    const { begin, enrolled, id } = await setupUser();
    const exerciseFlow = async (token: string) => {
      for (let attempt = 0; attempt < 5; attempt++) expect(await reserveMfaAttempt(env.DB, token, now)).toBe(true);
      expect(await reserveMfaAttempt(env.DB, token, now)).toBe(false);
    };
    await exerciseFlow(await begin("enroll", 0));
    await enrolled();
    for (let flow = 0; flow < 3; flow++) await exerciseFlow(await begin("login", 1));
    expect(await env.DB.prepare("SELECT totp_attempts, totp_retry_at FROM mfa_accounts WHERE user_id = ?")
      .bind(id).first()).toEqual({ totp_attempts: 0, totp_retry_at: 0 });
    expect(await reserveMfaAttempt(env.DB, await begin("login", 1), now, "totp")).toBe(true);
  });
});
