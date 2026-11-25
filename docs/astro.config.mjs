// @ts-check
import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";

// Served by GitHub Pages as a project site under the account domain: https://docs.i2bskn.com/workers-app-core/
export default defineConfig({
  site: "https://docs.i2bskn.com",
  base: "/workers-app-core",
  devToolbar: { enabled: false },
  integrations: [
    starlight({
      title: "workers-app-core",
      description:
        "Sign-in, user management and MCP OAuth for Hono apps on Cloudflare Workers with D1.",
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/i2bskn/workers-app-core" },
      ],
      customCss: [
        "@fontsource/ibm-plex-sans/latin-400.css",
        "@fontsource/ibm-plex-sans/latin-500.css",
        "@fontsource/ibm-plex-sans/latin-600.css",
        "@fontsource/ibm-plex-mono/latin-400.css",
        "@fontsource/ibm-plex-mono/latin-500.css",
        "./src/styles/theme.css",
      ],
      components: {
        SiteTitle: "./src/components/SiteTitle.astro",
        Hero: "./src/components/Hero.astro",
        SocialIcons: "./src/components/SocialIcons.astro",
      },
      expressiveCode: {
        themes: ["github-dark-dimmed", "github-light"],
        styleOverrides: {
          borderRadius: "10px",
          borderColor: "var(--gh-line)",
          codeFontFamily: "var(--__sl-font-mono)",
          uiFontFamily: "var(--__sl-font)",
          codeFontSize: "0.8125rem",
          codeLineHeight: "1.7",
          frames: {
            shadowColor: "transparent",
            editorTabBarBackground: "var(--gh-surface-2)",
            editorActiveTabBackground: "var(--gh-surface)",
            editorActiveTabIndicatorTopColor: "var(--sl-color-accent)",
            editorActiveTabIndicatorBottomColor: "transparent",
            editorBackground: "var(--gh-surface)",
            terminalBackground: "var(--gh-surface)",
            terminalTitlebarBackground: "var(--gh-surface-2)",
          },
        },
      },
      head: [
        {
          // Copy each column header to its cells, so stacked tables on phones can label the values.
          tag: "script",
          content: `document.addEventListener("DOMContentLoaded", () => {
  for (const table of document.querySelectorAll(".sl-markdown-content table")) {
    const labels = [...table.querySelectorAll("thead th")].map((th) => th.textContent.trim());
    for (const row of table.querySelectorAll("tbody tr")) {
      [...row.children].forEach((cell, i) => {
        if (labels[i]) cell.dataset.label = labels[i];
      });
    }
  }
});`,
        },
      ],
      editLink: { baseUrl: "https://github.com/i2bskn/workers-app-core/edit/main/docs/" },
      sidebar: [
        {
          label: "Getting started",
          items: ["getting-started/installation", "getting-started/usage"],
        },
        {
          label: "Guides",
          items: [
            "guides/configuration",
            "guides/users",
            "guides/password-mfa",
            "guides/database",
            "guides/mcp",
            "guides/browser-client",
            "guides/testing",
          ],
        },
        {
          label: "Reference",
          items: [
            "reference/create-core",
            "reference/hooks",
            "reference/security",
            "reference/upgrading",
          ],
        },
      ],
    }),
  ],
});
