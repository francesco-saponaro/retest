import type { Tool } from "@retest/schema";
import type { Principal } from "./auth.js";
import type { Db } from "./db/index.js";
import { createAssessment, requireAssessment, setAssessmentPhase, setAssessmentStatus } from "./services/assessments.js";
import { runImport, type ImportResult } from "./services/imports.js";

/**
 * The lab assessment, built from the fixtures in `packages/parsers/fixtures/` through the same
 * code path a real import takes. This file knows nothing about where the fixtures are: the CLI
 * seed reads them from disk, the demo build ships them inside the web app. Both call `seedLab`.
 */
export const LAB_RUNS: { tool: Tool; file: string; repository?: string }[] = [
  { tool: "nmap", file: "nmap/juice-shop.xml" },
  { tool: "nuclei", file: "nuclei/juice-shop.jsonl" },
  { tool: "zap", file: "zap/juice-shop.json" },
  { tool: "semgrep", file: "semgrep/juice-shop.sarif", repository: "juice-shop" },
  { tool: "trivy", file: "trivy/juice-shop-image.json" },
  { tool: "prowler", file: "prowler/lab-account.ocsf.json" },
];

/** Two minutes between one tool's import and the next, so the imports list reads in the order the lab ran them. */
export const IMPORT_SPACING = 2 * 60 * 1000;

export interface SeedOptions {
  ownerId: string;
  /** When the lab was authorised and scanned. The imports follow two minutes apart, as a run of the lab script would. */
  now?: Date;
  /** Read a fixture by its path under the fixtures folder. */
  read: (file: string) => string;
  /** A fixed id for the assessment, so a link to it survives a reload of the demo. Random when not given. */
  assessmentId?: string;
}

export interface SeedResult {
  assessmentId: string;
  imports: ImportResult[];
}

/**
 * Juice Shop on 127.0.0.1:3000, its source and its image, and a small cloud account, imported
 * through the six fixtures. The assessment is left active in phase 3, which is where scanner
 * output sits until someone validates it.
 */
export async function seedLab(db: Db, options: SeedOptions): Promise<SeedResult> {
  const who: Principal = { sub: options.ownerId, role: "assessor" };
  const now = options.now ?? new Date();
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
    options.assessmentId,
  );
  let row = await requireAssessment(db, created.id, who);
  await setAssessmentStatus(db, row, "active", who, "The lab is mine to scan.", now);
  row = await requireAssessment(db, created.id, who);
  await setAssessmentPhase(db, row, "assessment", who, "Scope and recon done by the lab script.", now);
  row = await requireAssessment(db, created.id, who);
  const imports: ImportResult[] = [];
  for (const [i, run] of LAB_RUNS.entries()) {
    const at = new Date(now.getTime() + (i + 1) * IMPORT_SPACING);
    imports.push(await runImport(db, row, { assessmentId: row.id, tool: run.tool, content: options.read(run.file), filename: run.file, ...(run.repository ? { repository: run.repository } : {}) }, who, at));
  }
  return { assessmentId: created.id, imports };
}
