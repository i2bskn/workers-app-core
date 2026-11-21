import { Hono, type Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { BrandLayout, BrandNames } from "../brand.js";
import { clock } from "../clock.js";
import type { UserRow } from "../db/schema.js";
import type { CoreEnv, CoreMiddleware } from "../auth/middleware.js";
import { safeNext } from "../auth/redirect.js";
import {
  beginMfa, cancelMfa, checkMfaEnrollment, checkMfaVerification, finishMfaEnrollment, finishMfaVerification, getMfaFactors, getMfaLoginState, MFA_PENDING_SECONDS, readMfa,
  reserveMfaAttempt, saveMfaTotpSecret, setMfaChallenge,
  type MfaEnrollment, type MfaFactors, type MfaPending, type MfaProof,
} from "../auth/mfa-store.js";
import {
  createRecoveryCodes, decryptTotpSecret, encryptTotpSecret, generateTotpSecret, hashRecoveryCode,
  verifyTotp,
} from "../auth/mfa-factors.js";
import type { PreparedSession } from "../auth/sessions.js";
import { ErrorPage } from "../views/error.js";
import { LoginPage } from "../views/login.js";
import { MfaPage, RecoveryCodesPage } from "../views/mfa.js";
import { mfaBrowserScript } from "../views/mfa-browser.js";

type Ctx = Context<CoreEnv>;
type Deps = {
  names: BrandNames;
  Layout: BrandLayout;
  middleware: CoreMiddleware;
  prepareSignIn: (c: Ctx, userId: string, setup: boolean) => Promise<{
    session: PreparedSession;
    setCookies(): void;
  }>;
};
const cookieOptions = { prefix: "host", path: "/", secure: true, httpOnly: true, sameSite: "Strict" } as const;
type Flow = { token: string; pending: MfaPending };

export function createPasswordMfa({ names, Layout, middleware, prepareSignIn }: Deps) {
  const cookieName = `${names.issuer}_mfa`;
  const routes = new Hono<CoreEnv>();
  routes.use("*", middleware.requireMode("password"));
  routes.use("*", middleware.sameOrigin);
  routes.use("*", async (c, next) => {
    c.header("Cache-Control", "no-store");
    await next();
  });

  function unavailable(c: Ctx) {
    return c.html(<ErrorPage Layout={Layout} message="手続きの有効期限が切れました。再度ログインしてください。" />, 401);
  }

  function failed(c: Ctx) {
    return c.html(<Layout title="認証エラー"><p role="alert">認証を完了できませんでした。</p><a href="/auth/mfa">再試行</a></Layout>, 400);
  }

  // Only the fixed origin configured by the deployer may issue WebAuthn options or accept assertions.
  function webauthnOrigin(c: Ctx) {
    const origin = c.get("config").passwordMfa.origin;
    return origin === new URL(c.req.url).origin ? origin : null;
  }

  function hasMethods(c: Ctx) {
    return Boolean(webauthnOrigin(c) || c.get("config").passwordMfa.key);
  }

  // Availability is checked before asking for proof and again before entering enrollment,
  // since the deployer may have changed the configured factors between requests.
  async function enrollmentProblem(c: Ctx, userId: string, adding: boolean) {
    if (!hasMethods(c)) {
      return c.html(<ErrorPage Layout={Layout} message="このURLで登録できる認証方法はありません。管理者に連絡してください。" />, 503);
    }
    if (adding && !webauthnOrigin(c) && (await getMfaFactors(c.get("db").$client, userId)).totp) {
      return c.html(<Layout title="認証方法の追加">
        <p>このURLで追加できる認証方法はすべて登録済みです。端末を変更するには「認証方法をすべて入れ替える」を選んでください。</p>
        <a href="/auth/mfa/manage">多要素認証の設定に戻る</a>
      </Layout>, 400);
    }
    return null;
  }

  async function start(c: Ctx, user: UserRow, next: string, action: unknown, setup: boolean) {
    const db = c.get("db").$client;
    const { policy } = c.get("config").passwordMfa;
    const state = await getMfaLoginState(db, user.id, policy);
    if (!state) return unavailable(c);
    const { revision, required } = state;
    const enrolled = revision > 0;
    const manage = action === "enroll" || action === "replace";
    if (action === "disable") {
      if (required) return c.html(<ErrorPage Layout={Layout} message="このアカウントには多要素認証が必須です。" />, 403);
      if (!enrolled) return c.html(<ErrorPage Layout={Layout} message="多要素認証は設定されていません。" />, 400);
    }
    if (!enrolled && !manage && !required) return null;
    if (!enrolled || manage) {
      const problem = await enrollmentProblem(c, user.id, enrolled && action === "enroll");
      if (problem) return problem;
    }
    if (!user.passwordHash) return unavailable(c);
    let purpose: MfaPending["purpose"] = "enroll";
    if (action === "disable") purpose = "disable";
    else if (enrolled) purpose = manage ? "manage" : "login";
    const token = await beginMfa(db, {
      userId: user.id, passwordHash: user.passwordHash, next, revision, policy, now: clock.now(),
      purpose,
      replace: enrolled && action === "replace", setup,
    });
    if (!token) return unavailable(c);
    setCookie(c, cookieName, token, { ...cookieOptions, maxAge: MFA_PENDING_SECONDS });
    return c.redirect("/auth/mfa", 303);
  }

  async function flow(c: Ctx): Promise<Flow | null> {
    const token = getCookie(c, cookieName, "host");
    if (!token) return null;
    const pending = await readMfa(c.get("db").$client, token, clock.now());
    return pending ? { token, pending } : null;
  }

  async function page(c: Ctx, pending: MfaPending, factors: MfaFactors) {
    const enroll = pending.purpose === "enroll";
    const { key } = c.get("config").passwordMfa;
    let totpSecret: string | undefined;
    if (enroll && pending.totpSecret && key) {
      try {
        totpSecret = await decryptTotpSecret(pending.totpSecret, key, pending.userId);
      } catch {
        return unavailable(c);
      }
    }
    return c.html(<MfaPage Layout={Layout} mode={enroll ? "enroll" : "verify"}
      webauthn={Boolean(webauthnOrigin(c) && (enroll || factors.credentials.length))}
      totp={Boolean(key && (enroll ? pending.replace || !factors.totp : factors.totp))}
      email={pending.email} issuer={names.issuer} totpSecret={totpSecret} replacing={pending.replace} recoveryEnrollment={pending.didUseRecoveryCode}
      recoveryLogin={pending.purpose === "login"} canReplace={hasMethods(c)} disabling={pending.purpose === "disable"} />);
  }

  async function enrollFactor(c: Ctx, { pending, token }: Flow, factor: MfaEnrollment) {
    const db = c.get("db").$client;
    if (!await checkMfaEnrollment(db, token, clock.now(), factor, pending.replace)) return failed(c);
    const codes = pending.revision === 0 || pending.replace || pending.didUseRecoveryCode
      ? await createRecoveryCodes()
      : { codes: [], hashes: [] };
    const prepared = await prepareSignIn(c, pending.userId, pending.setup);
    if (!await finishMfaEnrollment(db, token, clock.now(), factor, codes.hashes, pending.replace, prepared.session)) {
      return failed(c);
    }
    prepared.setCookies();
    deleteCookie(c, cookieName, cookieOptions);
    return codes.codes.length
      ? c.html(<RecoveryCodesPage Layout={Layout} codes={codes.codes} next={pending.next} />)
      : c.redirect(pending.next, 303);
  }

  async function verify(c: Ctx, { pending, token }: Flow, proof: MfaProof, replaceOnRecovery = false) {
    const db = c.get("db").$client;
    const { policy } = c.get("config").passwordMfa;
    const outcome = await checkMfaVerification(db, token, clock.now(), proof, policy, replaceOnRecovery);
    if (!outcome) return failed(c);
    async function enterEnrollment() {
      const problem = await enrollmentProblem(c, pending.userId, pending.purpose === "manage" && !pending.replace);
      if (problem) return problem;
      const options = { outcome: "enroll", replaceOnRecovery } as const;
      if (!await finishMfaVerification(db, token, clock.now(), proof, policy, options)) return failed(c);
      return c.redirect("/auth/mfa", 303);
    }
    if (outcome === "enroll") return enterEnrollment();
    const prepared = await prepareSignIn(c, pending.userId, false);
    if (!await finishMfaVerification(db, token, clock.now(), proof, policy, { outcome, replaceOnRecovery, session: prepared.session })) {
      // Another sign-in may have consumed the second-to-last code during the hook.
      if (pending.purpose === "login" && proof.kind === "recovery" &&
        await checkMfaVerification(db, token, clock.now(), proof, policy, replaceOnRecovery) === "enroll") {
        return enterEnrollment();
      }
      return failed(c);
    }
    prepared.setCookies();
    deleteCookie(c, cookieName, cookieOptions);
    if (pending.purpose === "disable") {
      return c.html(<Layout title="多要素認証の解除"><h1>多要素認証を解除しました</h1><a href={pending.next}>続ける</a></Layout>);
    }
    return c.redirect(pending.next, 303);
  }

  function limited(c: Ctx) {
    return c.html(<ErrorPage Layout={Layout} message="認証を続行できません。時間をおいて再度ログインしてください。" />, 429);
  }

  routes.get("/manage", (c) => c.html(<LoginPage Layout={Layout} manageMfa canDisableMfa={c.get("config").passwordMfa.policy !== "all"}
    next={safeNext(c.req.query("next"), new URL(c.req.url).origin)} />));
  routes.get("/browser.js", (c) => {
    c.header("Cache-Control", "public, no-cache");
    c.header("Content-Type", "text/javascript; charset=utf-8");
    return c.body(mfaBrowserScript);
  });
  routes.get("/", async (c) => {
    const state = await flow(c);
    if (!state) return unavailable(c);
    return page(c, state.pending, await getMfaFactors(c.get("db").$client, state.pending.userId));
  });
  routes.post("/totp/start", async (c) => {
    const state = await flow(c);
    if (!state) return unavailable(c);
    const { token, pending } = state;
    const key = c.get("config").passwordMfa.key;
    if (pending.purpose !== "enroll" || !key) return failed(c);
    const factors = await getMfaFactors(c.get("db").$client, pending.userId);
    if (!pending.replace && factors.totp) return failed(c);
    if (pending.totpSecret) return page(c, pending, factors);
    const encrypted = await encryptTotpSecret(generateTotpSecret(), key, pending.userId);
    const totpSecret = await saveMfaTotpSecret(c.get("db").$client, token, clock.now(), encrypted);
    if (!totpSecret) return unavailable(c);
    return page(c, { ...pending, totpSecret }, factors);
  });
  routes.post("/totp", async (c) => {
    const state = await flow(c);
    if (!state) return unavailable(c);
    const { token, pending } = state;
    const key = c.get("config").passwordMfa.key;
    if (!key) return failed(c);
    const { code } = await c.req.parseBody();
    const enroll = pending.purpose === "enroll";
    const db = c.get("db").$client;
    const secret = enroll ? pending.totpSecret : (await getMfaFactors(db, pending.userId)).totp?.secret;
    // Only guesses against a registered TOTP need an account-wide limit.
    if (!await reserveMfaAttempt(db, token, clock.now(), !enroll && secret ? "totp" : undefined)) return limited(c);
    if (!secret || typeof code !== "string") return failed(c);
    let plain: string;
    try {
      plain = await decryptTotpSecret(secret, key, pending.userId);
    } catch {
      return failed(c);
    }
    const step = await verifyTotp(plain, code, clock.now());
    if (step === null) return failed(c);
    return enroll ? enrollFactor(c, state, { kind: "totp", step, secret }) : verify(c, state, { kind: "totp", step });
  });
  routes.post("/recovery", async (c) => {
    const state = await flow(c);
    if (!state) return unavailable(c);
    if (state.pending.purpose === "enroll") return failed(c);
    const { code, mfa } = await c.req.parseBody();
    if (!await reserveMfaAttempt(c.get("db").$client, state.token, clock.now())) return limited(c);
    if (typeof code !== "string") return failed(c);
    return verify(c, state, { kind: "recovery", hash: await hashRecoveryCode(code) }, state.pending.purpose === "login" && mfa === "replace");
  });
  routes.post("/webauthn/options", async (c) => {
    const state = await flow(c);
    if (!state) return unavailable(c);
    const origin = webauthnOrigin(c);
    if (!origin) return failed(c);
    const { token, pending } = state;
    const db = c.get("db").$client;
    const { credentials } = await getMfaFactors(db, pending.userId);
    const { webauthnRegistrationOptions, webauthnAuthenticationOptions } = await import("../auth/webauthn.js");
    const options = pending.purpose === "enroll"
      ? await webauthnRegistrationOptions(origin, names.issuer, { id: pending.userId, email: pending.email }, credentials)
      : await webauthnAuthenticationOptions(origin, credentials);
    if (!await setMfaChallenge(db, token, clock.now(), options.challenge)) return unavailable(c);
    return c.json(options);
  });
  routes.post("/webauthn/verify", async (c) => {
    const state = await flow(c);
    if (!state) return unavailable(c);
    const { token, pending } = state;
    const origin = webauthnOrigin(c);
    const { challenge } = pending;
    if (!origin || !challenge) return failed(c);
    if (!await reserveMfaAttempt(c.get("db").$client, token, clock.now())) return limited(c);
    const { response } = await c.req.parseBody();
    if (typeof response !== "string" || response.length > 65536) return failed(c);
    let credential: unknown;
    try {
      credential = JSON.parse(response);
    } catch {
      return failed(c);
    }
    const { verifyWebauthnRegistration, verifyWebauthnAuthentication } = await import("../auth/webauthn.js");
    if (pending.purpose === "enroll") {
      const verified = await verifyWebauthnRegistration(origin, challenge, credential);
      return verified ? enrollFactor(c, state, { kind: "webauthn", challenge, credential: verified }) : failed(c);
    }
    if (!credential || typeof credential !== "object" || !("id" in credential)) return failed(c);
    const { credentials } = await getMfaFactors(c.get("db").$client, pending.userId);
    const saved = credentials.find((item) => item.id === credential.id);
    if (!saved) return failed(c);
    const counter = await verifyWebauthnAuthentication(origin, challenge, credential, saved);
    return counter === null ? failed(c) : verify(c, state, { kind: "webauthn", challenge, id: saved.id, counter });
  });
  async function cancel(c: Ctx) {
    const token = getCookie(c, cookieName, "host");
    if (!token) return;
    await cancelMfa(c.get("db").$client, token);
    deleteCookie(c, cookieName, cookieOptions);
  }
  return { start, routes, cancel, hasMethods };
}
