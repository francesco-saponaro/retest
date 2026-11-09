import { z } from "zod";
import type { Db } from "./db/index.js";
import { connect, connectPglite } from "./db/migrate.js";

/**
 * Everything the API reads from the environment, checked once at start. There is no default for
 * the JWT secret on purpose: an API that starts with a known secret is an API anyone can sign for.
 */
const EnvSchema = z.object({
  /** `postgres://…` for PostgreSQL; `pglite` for an in-process database in memory; `pglite:./data` to keep it on disk. */
  DATABASE_URL: z.string().min(1).default("pglite"),
  RETEST_JWT_SECRET: z.string().min(32, "RETEST_JWT_SECRET must be at least 32 characters"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  /** Loopback by default. The lab binds everything to 127.0.0.1; a deployment sets 0.0.0.0 on purpose. */
  HOST: z.string().min(1).default("127.0.0.1"),
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(300),
  IMPORT_RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(20),
  SEED_OWNER: z.string().min(1).default("lab"),
  LOG: z.enum(["true", "false"]).default("true"),
});

export interface Config {
  databaseUrl: string;
  jwtSecret: string;
  port: number;
  host: string;
  rateLimitMax: number;
  importRateLimitMax: number;
  seedOwner: string;
  logger: boolean;
}

export function config(env: NodeJS.ProcessEnv = process.env): Config {
  const r = EnvSchema.safeParse(env);
  if (!r.success) {
    const lines = r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    throw new Error(`bad configuration:\n  ${lines.join("\n  ")}`);
  }
  return {
    databaseUrl: r.data.DATABASE_URL,
    jwtSecret: r.data.RETEST_JWT_SECRET,
    port: r.data.PORT,
    host: r.data.HOST,
    rateLimitMax: r.data.RATE_LIMIT_MAX,
    importRateLimitMax: r.data.IMPORT_RATE_LIMIT_MAX,
    seedOwner: r.data.SEED_OWNER,
    logger: r.data.LOG === "true",
  };
}

/** The database the configuration names, migrated and ready. */
export async function openDatabase(c: Config): Promise<{ db: Db; close: () => Promise<void> }> {
  if (c.databaseUrl === "pglite") return connectPglite();
  if (c.databaseUrl.startsWith("pglite:")) return connectPglite(c.databaseUrl.slice("pglite:".length));
  return connect(c.databaseUrl);
}
