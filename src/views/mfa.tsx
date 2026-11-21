import type { BrandLayout } from "../brand.js";

type MfaPageProps = {
  Layout: BrandLayout;
  mode: "enroll" | "verify";
  webauthn: boolean;
  totp: boolean;
  totpSecret?: string;
  email?: string;
  issuer?: string;
  error?: string;
  replacing?: boolean;
  disabling?: boolean;
  recoveryLogin?: boolean;
  recoveryEnrollment?: boolean;
  canReplace?: boolean;
};

async function TotpSetup({ secret, email, issuer }: { secret: string; email: string; issuer: string }) {
  const parameters = new URLSearchParams({ secret, issuer, algorithm: "SHA1", digits: "6", period: "30" });
  const uri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?${parameters}`;
  const { renderSVG } = await import("uqr");
  const svg = renderSVG(uri);
  return (
    <>
      <p>認証アプリでQRコードを読み取るか、セットアップキーを手入力してください。</p>
      <img src={`data:image/svg+xml;charset=UTF-8,${encodeURIComponent(svg)}`} width="232" height="232" alt="認証アプリ登録用QRコード" />
      <p>セットアップキー <code>{secret}</code></p>
    </>
  );
}

export function MfaPage(props: MfaPageProps) {
  const { Layout, mode, totpSecret, replacing } = props;
  const enrolling = mode === "enroll";
  const title = props.disabling ? "多要素認証の解除" : enrolling ? "認証方式の登録" : "2段階認証";
  return (
    <Layout title={title}>
      <h1>{title}</h1>
      {props.error ? <p role="alert">{props.error}</p> : null}
      {props.disabling ? <p>現在の認証方法または復旧コードで確認すると、登録した認証方法と復旧コードがすべて削除されます。</p> : null}
      {replacing && enrolling ? <p>新しい認証方式を確認すると、既存の認証方式と復旧コードが置き換わります。登録済みのパスキーを交換する場合は、別の認証器を使ってください。</p> : null}
      {enrolling && !replacing && props.recoveryEnrollment && (
        <p>新しい認証方法を追加すると、復旧コードも新しくなります。次の画面で保存してください。</p>
      )}
      {props.webauthn ? (
        <>
          <form method="post" action="/auth/mfa/webauthn/verify" data-webauthn={mode}>
            <input type="hidden" name="response" />
            <button type="submit" class="primary">
              {enrolling ? "パスキー・セキュリティキーを登録" : "パスキー・セキュリティキーで確認"}
            </button>
            <p role="status" aria-live="polite"></p>
          </form>
          <script src="/auth/mfa/browser.js" defer></script>
        </>
      ) : null}
      {!props.webauthn && enrolling ? <p>パスキーは、管理者が設定した公開URLで登録できます。</p> : null}
      {props.totp && enrolling && !totpSecret ? (
        <form method="post" action="/auth/mfa/totp/start">
          <button type="submit">認証アプリ（TOTP）を登録</button>
        </form>
      ) : null}
      {props.totp && (!enrolling || totpSecret) ? (
        <form method="post" action="/auth/mfa/totp">
          {totpSecret ? <TotpSetup secret={totpSecret} email={props.email ?? ""} issuer={props.issuer ?? "TOTP"} /> : null}
          <p><label>認証アプリの6桁のコード
            <input name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength={6} required />
          </label></p>
          <button type="submit">{enrolling ? "認証アプリの登録を完了" : "認証コードを確認"}</button>
        </form>
      ) : null}
      {!props.webauthn && !props.totp && enrolling ? <p>この画面から追加できる認証方式はありません。管理者に連絡してください。</p> : null}
      {!enrolling ? (
        <details>
          <summary>復旧コードを使う</summary>
          <form method="post" action="/auth/mfa/recovery">
            <p><label>未使用の復旧コード<input type="text" name="code" autocomplete="off" required /></label></p>
            {props.recoveryLogin && <p>最後の復旧コードを使うと、新しい認証方法の登録に進みます。</p>}
            <button type="submit">復旧コードで確認</button>
            {props.recoveryLogin && props.canReplace && (
              <button type="submit" name="mfa" value="replace">復旧コードで認証方法を入れ替える</button>
            )}
          </form>
        </details>
      ) : null}
    </Layout>
  );
}

export function RecoveryCodesPage({ Layout, codes, next }: { Layout: BrandLayout; codes: string[]; next: string }) {
  return (
    <Layout title="復旧コード">
      <h1>復旧コード</h1>
      <p>認証端末を使えないときに、パスワードと一緒に使います。各コードは1回限りです。この画面を閉じる前に安全な場所に保存してください。</p>
      <ul>{codes.map((code) => <li><code>{code}</code></li>)}</ul>
      <a href={next}>続ける</a>
    </Layout>
  );
}
