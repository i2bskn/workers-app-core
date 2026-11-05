import { html } from "hono/html";
import type { Brand, BrandLayout } from "../brand.js";

export const DEFAULT_SERVER_PAGES_CSS = "/server-pages.css";

// The default layout of the screens served by the Worker (login, setup, consent, errors). They are styled by a
// static stylesheet (brand.serverPagesCss).
export function createDefaultLayout(brand: Brand): BrandLayout {
  const stylesheet = brand.serverPagesCss ?? DEFAULT_SERVER_PAGES_CSS;
  return (props) =>
    html`<!DOCTYPE html>${(
      <html lang="ja">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <meta name="theme-color" content="#f4f5f2" media="(prefers-color-scheme: light)" />
          <meta name="theme-color" content="#121617" media="(prefers-color-scheme: dark)" />
          <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
          <link rel="stylesheet" href={stylesheet} />
          <title>{`${props.title} - ${brand.name}`}</title>
        </head>
        <body>
          <div class="shell">
            <a href="/" class="brand">
              <span class="brand-wordmark">{brand.name}</span>
            </a>
            {brand.tagline === undefined ? null : <p class="tagline">{brand.tagline}</p>}
            <main class="card">{props.children}</main>
          </div>
        </body>
      </html>
    )}`;
}
