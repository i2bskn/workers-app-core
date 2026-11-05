import type { D1Migration } from "cloudflare:test";
import type { FixtureBindings } from "./fixture/src/index.js";

declare global {
  namespace Cloudflare {
    interface Env extends FixtureBindings {
      TEST_MIGRATIONS: D1Migration[];
    }
  }
}
