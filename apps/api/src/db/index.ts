import type { PgDatabase, PgQueryResultHKT } from "drizzle-orm/pg-core";
import * as schema from "./schema.js";

/**
 * The database as the rest of the API sees it: a Drizzle handle over the tables in `schema.ts`.
 * In production it is `node-postgres` against PostgreSQL 16; in the tests and the seed it is
 * PGlite, PostgreSQL compiled to WebAssembly, running in the process. The queries are the same.
 */
export type Db = PgDatabase<PgQueryResultHKT, typeof schema>;

export { schema };
export * from "./schema.js";
