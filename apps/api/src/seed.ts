import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Tool } from "@retest/schema";
import type { Principal } from "./auth.js";
import { config, openDatabase } from "./config.js";
import type { Db } from "./db/index.js";
import { createAssessment, requireAssessment, setAssessmentPhase, setAssessmentStatus } from "./services/assessments.js";
import { runImport, type ImportResult } from "./services/imports.js";

/** The fixtures in `packages/parsers/fixtures/`, as the lab would have produced them. */
export const fixturesDir = fileURLToPath(new URL("../../../packages/parsers/fixtures/", import.meta.url));

export const LAB_RUNS: { tool: Tool; file: string; repository?: string }[] = [
  { tool: "nmap", file: "nmap/juice-shop.xml" },
  { tool: "nuclei", file: "nuclei/juice-shop.jsonl" },
  { tool: "zap", file: "zap/juice-shop.json" },
  { tool: "semgrep", file: "semgrep/juice-shop.sarif", repository: "juice-shop" },
  { tool: "trivy", file: "trivy/juice-shop-image.json" },
  { tool: "prowler", file: "prowler/lab-account.ocsf.json" },
];

export interface SeedOptions {
  ownerId: string;
  now?: Date;
  /** Read a fixture by its path under the fixtures folder. Defaults to the files on disk. */
  read?: (file: string) => string;
}

export interface SeedResult {
  assessmentId: string;
  imports: ImportResult[];
}

/**
 * The lab assessment: Juice Shop on 127.0.0.1:3000, its source and its image, two lab VMs'
 * worth of Nmap and a small cloud account, imported through the same code path a real import
 * takes. The assessment is left active in phase 3, which is where scanner output sits until
 * someone validates it.
 */
export async function seedLab(db: Db, options: SeedOptions): Promise<SeedResult> {
  const who: Principal = { sub: options.ownerId, role: "assessor" };
  const now = options.now ?? new Date();
  const read = options.read ?? ((file) => readFileSync(new URL(file, `file://${fixturesDir}`), "utf8"));
  const created = await createAssessment(
    db,
    {
      name: "Juice Shop lab",
      client: "Retest lab",
      scope: {
        targets: ["127.0.0.1", "http://127.0.0.1:3000", "juice-shop", "bkimminich/juice-shop:v17.1.1", "123456789012"],
        exclusions: [],
        authorizedBy: options.ownerId,
        authorizedAt: now.toISOString(),
      },
    },
    who,
    now,
  );
  let row = await requireAssessment(db, created.id, who);
  await setAssessmentStatus(db, row, "active", who, "The lab is mine to scan.", now);
  row = await requireAssessment(db, created.id, who);
  await setAssessmentPhase(db, row, "assessment", who, "Scope and recon done by the lab script.", now);
  row = await requireAssessment(db, created.id, who);
  const imports: ImportResult[] = [];
  for (const run of LAB_RUNS) {
    imports.push(await runImport(db, row, { assessmentId: row.id, tool: run.tool, content: read(run.file), filename: run.file, ...(run.repository ? { repository: run.repository } : {}) }, who, now));
  }
  return { assessmentId: created.id, imports };
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
