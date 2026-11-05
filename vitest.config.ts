import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations("test/fixture/drizzle/migrations");
  return {
    test: {
      projects: [
        // Worker tests against the fixture app, run in workerd.
        {
          plugins: [
            cloudflareTest({
              wrangler: { configPath: "./test/fixture/wrangler.jsonc" },
              miniflare: {
                bindings: {
                  TEST_MIGRATIONS: migrations,
                  AUTH_MODE: "password",
                  JWT_SECRET: "test-secret-test-secret-test-secret-0123",
                },
              },
            }),
          ],
          test: {
            name: "worker",
            include: ["test/*.test.ts"],
            setupFiles: ["./test/setup.ts"],
            testTimeout: 30000,
          },
        },
        // The browser-safe client entry, run in Node.
        {
          test: {
            name: "node",
            include: ["test/node/**/*.test.ts"],
            environment: "node",
          },
        },
      ],
    },
  };
});
