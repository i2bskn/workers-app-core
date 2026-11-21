import type { BrandLayout } from "../brand.js";

// The page of an invitation link: the invited user sets their password. The token travels in a hidden field.
export function InvitePage(props: { Layout: BrandLayout; token: string; email: string; errors?: string[] }) {
  const { Layout } = props;
  return (
    <Layout title="パスワードの設定">
      <h1>パスワードの設定</h1>
      <p class="lead">招待を受けたアカウントのパスワードを決めてください。</p>
      {props.errors && props.errors.length > 0 ? (
        <ul role="alert">
          {props.errors.map((error) => (
            <li>{error}</li>
          ))}
        </ul>
      ) : null}
      <form method="post" action="/auth/invite">
        <input type="hidden" name="token" value={props.token} />
        <p>
          <label>
            メールアドレス
            <input type="email" name="email" value={props.email} autocomplete="username" readonly />
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
          パスワードを設定
        </button>
      </form>
    </Layout>
  );
}
