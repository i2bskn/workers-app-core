import { drizzle } from "drizzle-orm/d1";

// Without a schema: the relational query API (db.query.*) is not used. db.$client is the D1 binding.
export function createDb(d1: D1Database) {
  return drizzle(d1);
}

export type Db = ReturnType<typeof createDb>;
