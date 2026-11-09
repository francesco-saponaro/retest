import { fileURLToPath } from "node:url";
import { drizzle as drizzlePg } from "drizzle-orm/node-postgres";
import { migrate as migratePg } from "drizzle-orm/node-postgres/migrator";
import { drizzle as drizzlePglite } from "drizzle-orm/pglite";
import { migrate as migratePglite } from "drizzle-orm/pglite/migrator";
import pg from "pg";
import * as schema from "./schema.js";
import type { Db } from "./index.js";

/** The SQL files `drizzle-kit generate` writes, committed next to the code that matches them. */
export const migrationsFolder = fileURLToPath(new URL("../../drizzle/", import.meta.url));

/** A connection to PostgreSQL with the migrations applied. */
export async function connect(url: string): Promise<{ db: Db; close: () => Promise<void> }> {
  const pool = new pg.Pool({ connectionString: url });
  const db = drizzlePg(pool, { schema });
  await migratePg(db, { migrationsFolder });
  return { db, close: () => pool.end() };
}

/** PostgreSQL in the process, in memory unless a data directory is given, with the migrations applied. */
export async function connectPglite(dataDir?: string): Promise<{ db: Db; close: () => Promise<void> }> {
  const { PGlite } = await import("@electric-sql/pglite");
  const client = dataDir ? new PGlite(dataDir) : new PGlite();
  const db = drizzlePglite(client, { schema });
  await migratePglite(db, { migrationsFolder });
  return { db, close: () => client.close() };
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const url = process.env["DATABASE_URL"];
  if (!url) {
    console.error("DATABASE_URL is not set");
    process.exit(1);
  }
  const { close } = await connect(url);
  console.log("migrations applied");
  await close();
}
