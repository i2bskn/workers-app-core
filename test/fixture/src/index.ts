import { Hono } from "hono";
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import {
  apiError,
  createCore,
  describeError,
  isJsonPath,
  type AppEnv,
  type CoreBindings,
  type CoreHooks,
  type McpOptions,
} from "../../../src/index.js";

// A minimal app built with createCore, for the package tests.

export type FixtureBindings = CoreBindings;
type Env = AppEnv<FixtureBindings>;
export type FixtureProps = { noteId?: string };
export type FixtureExtra = { label: string } | undefined;

// A table of the app, used by the hook tests.
export const userNotes = sqliteTable("user_notes", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  userId: text("user_id").notNull(),
  note: text("note").notNull(),
});

export const BRAND_ID = "testapp";
export const CONSENT_DESCRIPTION = "Once allowed, this app can read the notes of your account.";

// The hooks and MCP callbacks of the core. Tests set them and reset() removes them.
export const hooks: CoreHooks<FixtureBindings, unknown> = {};

export const mcpCalls: { extra: FixtureExtra; props: Record<string, unknown> }[] = [];

export const mcp: McpOptions<FixtureBindings, FixtureProps, FixtureExtra> = {
  serverInfo: { name: "testapp", version: "0.0.0" },
  register: (server, { extra, props, user }) => {
    mcpCalls.push({ extra, props: { ...props } });
    server.registerTool("whoami", { description: "The signed-in user.", inputSchema: {} }, () => ({
      content: [{ type: "text", text: JSON.stringify({ email: user.email, extra: extra ?? null }) }],
    }));
  },
};

export function reset(): void {
  for (const key of Object.keys(hooks)) delete hooks[key as keyof typeof hooks];
  delete mcp.parseProps;
  delete mcp.checkRequest;
  mcpCalls.length = 0;
}

export const core = createCore<FixtureBindings, object, FixtureProps, FixtureExtra, unknown>({
  brand: { id: BRAND_ID, name: "Testapp", tagline: "A test app." },
  hooks,
  mcp,
  consent: { description: CONSENT_DESCRIPTION },
});

const { securityHeaders, loadConfigMiddleware, unifyHost, sameOrigin } = core.middleware;

export const app = new Hono<Env>();

app.use("*", securityHeaders);
app.use("*", loadConfigMiddleware);
app.use("*", unifyHost);
app.use("/auth/*", sameOrigin);
app.use("/api/v1/*", sameOrigin);
app.use("/authorize", sameOrigin);

app.route("/auth", core.routes.auth);
app.route("/authorize", core.routes.authorize);
const apiRoutes = app.route("/api/v1/me", core.routes.me).route("/api/v1/users", core.routes.users);

export type AppType = typeof apiRoutes;

app.notFound((c) => {
  if (isJsonPath(c.req.path)) return apiError(c, 404, "not_found", "見つかりません");
  return c.html(core.ErrorPage({ message: "ページが見つかりません" }), 404);
});

app.onError((error, c) => {
  console.error("unhandled error", describeError(error));
  if (isJsonPath(c.req.path)) return apiError(c, 500, "internal_error", "サーバーでエラーが発生しました");
  return c.html(core.ErrorPage({ message: "サーバーでエラーが発生しました" }), 500);
});

export default {
  fetch: core.fetch(app),
} satisfies ExportedHandler<FixtureBindings>;
