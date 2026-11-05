import type { BrandLayout } from "../brand.js";

export function LoggedOutPage(props: { Layout: BrandLayout }) {
  const { Layout } = props;
  return (
    <Layout title="ログアウト">
      <h1>ログアウトしました</h1>
      <p>
        <a href="/auth/login" class="button">
          ログイン
        </a>
      </p>
    </Layout>
  );
}
