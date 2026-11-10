import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { config, openDatabase } from "./config.js";
import type { Db } from "./db/index.js";
import { seedLab as seedLabFrom, type SeedOptions, type SeedResult } from "./lab.js";

export { LAB_RUNS } from "./lab.js";
export type { SeedOptions, SeedResult } from "./lab.js";

/** The fixtures in `packages/parsers/fixtures/`, as the lab would have produced them. */
export const fixturesDir = fileURLToPath(new URL("../../../packages/parsers/fixtures/", import.meta.url));

/** The lab assessment, with the fixtures read from disk unless a reader is given. */
export function seedLab(db: Db, options: Omit<SeedOptions, "read"> & Partial<Pick<SeedOptions, "read">>): Promise<SeedResult> {
  const read = options.read ?? ((file: string) => readFileSync(new URL(file, `file://${fixturesDir}`), "utf8"));
  return seedLabFrom(db, { ...options, read });
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const ownerId = process.argv[2] ?? config().seedOwner;
  const { db, close } = await openDatabase(config());
  try {
    const result = await seedLab(db, { ownerId });
    console.log(`assessment ${result.assessmentId} for ${ownerId}`);
    for (const i of result.imports) console.log(`  ${i.tool.padEnd(8)} ${i.parsed} parsed, ${i.created} created, ${i.merged} merged${i.warnings.length ? `, ${i.warnings.length} warning(s)` : ""}`);
  } finally {
    await close();
  }
}
