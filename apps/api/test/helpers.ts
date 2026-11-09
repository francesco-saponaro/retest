import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import type { SQL } from "drizzle-orm";
import { drizzle } from "drizzle-orm/pglite";
import { migrate } from "drizzle-orm/pglite/migrator";
import * as schema from "../src/db/schema.js";
import { migrationsFolder } from "../src/db/migrate.js";
import type { Db } from "../src/db/index.js";

export interface TestDb {
  db: Db;
  migrate: () => Promise<void>;
  /** Empty every table. */
  reset: () => Promise<void>;
  close: () => Promise<void>;
}

/** An in-memory PostgreSQL with the migrations applied. One per test file. */
export async function testDb(): Promise<TestDb> {
  const client = new PGlite();
  const db = drizzle(client, { schema });
  const run = () => migrate(db, { migrationsFolder });
  await run();
  return {
    db,
    migrate: run,
    reset: async () => {
      await client.exec("delete from imports; delete from audit_log; delete from evidence; delete from findings; delete from assets; delete from assessments;");
    },
    close: () => client.close(),
  };
}

/** Run raw SQL and get the rows, typed by the caller. */
export async function rows<T>(db: Db, query: SQL): Promise<T[]> {
  return ((await db.execute(query)) as unknown as { rows: T[] }).rows;
}

const fixtures = fileURLToPath(new URL("../../../packages/parsers/fixtures/", import.meta.url));

/** Read a file from `packages/parsers/fixtures/`. */
export function fixture(path: string): string {
  return readFileSync(join(fixtures, path), "utf8");
}
