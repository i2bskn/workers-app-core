import type { ConsentDescription } from "@cloudflare/workers-oauth-provider";
import type { BrandLayout } from "../brand.js";

export type ConsentPageProps = {
  details: ConsentDescription;
  handle: string;
  email: string;
  // consent.description: what the client can do once allowed.
  description: string | undefined;
};

// Every string in details may come from the client. JSX escapes them.
export function ConsentPage(props: ConsentPageProps & { Layout: BrandLayout }) {
  const { details, Layout } = props;
  return (
    <Layout title="接続の許可">
      <h1>{details.clientName} からの接続を許可しますか？</h1>
      {details.clientDomain ? (
        <p>
          このアプリは <strong>{details.clientDomain}</strong> が公開しています。
        </p>
      ) : (
        <p>このアプリの名前は確認されていません。</p>
      )}
      <p>
        接続は <strong>{details.redirectHost}</strong> に渡されます。
      </p>
      {details.redirectIsLoopback ? (
        <p role="alert" class="warning">
          <strong>このパソコン上のアプリに接続を渡します。今そのアプリから接続を始めた場合だけ許可してください。</strong>
        </p>
      ) : null}
      <p>ログイン中のユーザー: {props.email}</p>
      <p>{props.description}</p>
      <form method="post" action="/authorize">
        <input type="hidden" name="handle" value={props.handle} />
        <div class="buttons">
          <button type="submit" name="decision" value="approve" class="primary">
            許可する
          </button>
          <button type="submit" name="decision" value="deny">
            拒否する
          </button>
        </div>
      </form>
    </Layout>
  );
}
