import type { BrandLayout } from "../brand.js";

export function LoginPage(props: { Layout: BrandLayout; next: string; email?: string; error?: string; manageMfa?: boolean; canDisableMfa?: boolean }) {
  const { Layout } = props;
  const title = props.manageMfa ? "多要素認証の設定" : "ログイン";
  return (
    <Layout title={title}>
      <h1>{title}</h1>
      {props.error ? <p role="alert">{props.error}</p> : null}
      <form method="post" action="/auth/login">
        <input type="hidden" name="next" value={props.next} />
        <p>
          <label>
            メールアドレス
            <input type="email" name="email" value={props.email ?? ""} autocomplete="username" required />
          </label>
        </p>
        <p>
          <label>
            パスワード
            <input type="password" name="password" autocomplete="current-password" required />
          </label>
        </p>
        {props.manageMfa ? (
          <>
            <button type="submit" name="mfa" value="enroll" class="primary">認証方法を登録・追加</button>
            <button type="submit" name="mfa" value="replace">認証方法をすべて入れ替える</button>
            {props.canDisableMfa && <button type="submit" name="mfa" value="disable">多要素認証を解除</button>}
          </>
        ) : <button type="submit" class="primary">ログイン</button>}
      </form>
      {!props.manageMfa && <p><a href={`/auth/mfa/manage?next=${encodeURIComponent(props.next)}`}>多要素認証の設定</a></p>}
    </Layout>
  );
}
