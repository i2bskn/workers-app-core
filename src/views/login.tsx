import type { BrandLayout } from "../brand.js";

export function LoginPage(props: { Layout: BrandLayout; next: string; email?: string; error?: string }) {
  const { Layout } = props;
  return (
    <Layout title="ログイン">
      <h1>ログイン</h1>
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
        <button type="submit" class="primary">
          ログイン
        </button>
      </form>
    </Layout>
  );
}
