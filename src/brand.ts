import type { Child } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";

// The markup returned by a page component.
export type PageMarkup = HtmlEscapedString | Promise<HtmlEscapedString>;

export type BrandLayout = (props: { title: string; children: Child }) => PageMarkup;

export type Brand = {
  // Lowercase letters, digits and "-", starting with a letter, up to 31 characters. Names the cookies and the JWTs.
  id: string;
  // The name shown on the server pages.
  name: string;
  tagline?: string;
  // The stylesheet of the server pages. Default: /server-pages.css.
  serverPagesCss?: string;
  // Replaces the default layout of the server pages.
  layout?: BrandLayout;
};

export const BRAND_ID_PATTERN = /^[a-z][a-z0-9-]{0,30}$/;

// The names derived from the brand ID.
export type BrandNames = {
  // Cookie names without the "__Host-" prefix; hono adds it via `prefix: "host"`.
  accessCookie: string;
  refreshCookie: string;
  oidcCookie: string;
  issuer: string;
  accessAudience: string;
  oidcAudience: string;
};

export function brandNames(id: string): BrandNames {
  if (!BRAND_ID_PATTERN.test(id)) throw new Error(`invalid brand id: ${JSON.stringify(id)}`);
  return {
    accessCookie: `${id}_at`,
    refreshCookie: `${id}_rt`,
    oidcCookie: `${id}_oidc`,
    issuer: id,
    accessAudience: `${id}-web`,
    oidcAudience: `${id}-oidc`,
  };
}
