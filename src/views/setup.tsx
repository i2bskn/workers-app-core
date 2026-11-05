import type { BrandLayout } from "../brand.js";

export function SetupPage(props: { Layout: BrandLayout; email?: string; name?: string; errors?: string[] }) {
  const { Layout } = props;
  return (
    <Layout title="初期設定">
      <h1>初期設定</h1>
      <p class="lead">最初の管理者アカウントを作成します。</p>
      {props.errors && props.errors.length > 0 ? (
        <ul role="alert">
          {props.errors.map((error) => (
            <li>{error}</li>
          ))}
        </ul>
      ) : null}
      <form method="post" action="/auth/setup">
        <p>
          <label>
            メールアドレス
            <input type="email" name="email" value={props.email ?? ""} autocomplete="username" required />
          </label>
        </p>
        <p>
          <label>
            名前（任意）
            <input type="text" name="name" value={props.name ?? ""} autocomplete="name" />
          </label>
        </p>
        <p>
          <label>
            パスワード（12 文字以上）
            <input type="password" name="password" autocomplete="new-password" required />
          </label>
        </p>
        <p>
          <label>
            パスワード（確認）
            <input type="password" name="password_confirm" autocomplete="new-password" required />
          </label>
        </p>
        <button type="submit" class="primary">
          作成
        </button>
      </form>
    </Layout>
  );
}
