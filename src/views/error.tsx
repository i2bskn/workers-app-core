import type { BrandLayout } from "../brand.js";

export function ErrorPage(props: { Layout: BrandLayout; message: string }) {
  const { Layout } = props;
  return (
    <Layout title="エラー">
      <h1>エラー</h1>
      <p>{props.message}</p>
      <p>
        <a href="/" class="button">
          トップへ戻る
        </a>
      </p>
    </Layout>
  );
}
