import { ToolSchema, type Asset, type Finding } from "@retest/schema";
import { canParse, classify, dedupe, normalize, parse, type ParseResult } from "@retest/parsers";
import { desc, eq, inArray } from "drizzle-orm";
import { z } from "zod";
import type { Principal } from "../auth.js";
import { assets, evidence, findings, imports, type AssessmentRow, type Db, type ImportRow } from "../db/index.js";
import { HttpError, newId } from "../http.js";
import { fromAsset, fromEvidence, fromFinding, toAsset, toFinding, toImport, type ImportOut } from "../rows.js";
import { record } from "./audit.js";
import { coveredByScope } from "./scope.js";

/** The envelope of a JSON import. A raw-body import takes the same fields from the query, with the body as `content`. */
export const ImportBodySchema = z.strictObject({
  assessmentId: z.string().min(1).max(100),
  tool: ToolSchema,
  content: z.string().min(1),
  filename: z.string().min(1).max(300).optional(),
  /** Semgrep only: SARIF does not say which repository was scanned. */
  repository: z.string().min(1).max(200).optional(),
});

export const ImportQuerySchema = ImportBodySchema.omit({ content: true });

export type ImportInput = z.infer<typeof ImportBodySchema>;

export interface ImportResult extends ImportOut {
  unmapped: { cwe: number[]; checks: string[] };
  notes: string[];
}

/**
 * One import: parse the file, normalise what the parser found onto the assessment's assets,
 * fold it into the findings that already exist, classify, and write what changed. Importing the
 * same file twice changes nothing: the ids are deterministic and the second copy merges into the
 * first. An asset the scope does not cover is still recorded, as out of scope, with a warning.
 */
export async function runImport(db: Db, assessment: AssessmentRow, input: ImportInput, who: Principal, now = new Date()): Promise<ImportResult> {
  if (assessment.status === "closed") throw new HttpError(409, "the assessment is closed");
  if (!canParse(input.tool)) throw new HttpError(400, "invalid body", [{ path: "tool", message: `no parser for ${input.tool}` }]);
  if (input.tool === "semgrep" && !input.repository) {
    throw new HttpError(400, "invalid body", [{ path: "repository", message: "a Semgrep import needs the repository name: SARIF does not carry it" }]);
  }

  let raw: ParseResult;
  try {
    raw = parse(input.tool, input.content, input.repository ? { repository: input.repository } : {});
  } catch (e) {
    throw new HttpError(400, `could not parse the ${input.tool} file: ${e instanceof Error ? e.message : String(e)}`);
  }

  const existingAssets = (await db.select().from(assets).where(eq(assets.assessmentId, assessment.id))).map(toAsset);
  const existingRows = await db.select().from(findings).where(eq(findings.assessmentId, assessment.id));
  const existingEvidence = existingRows.length ? await db.select().from(evidence).where(inArray(evidence.findingId, existingRows.map((r) => r.id))) : [];
  const existing = existingRows.map((r) => toFinding(r, existingEvidence.filter((e) => e.findingId === r.id)));
  const existingIds = new Set(existing.map((f) => f.id));
  const existingEvidenceIds = new Set(existingEvidence.map((e) => e.id));

  const normalized = normalize(raw.findings, { assessmentId: assessment.id, assets: existingAssets, now });
  const warnings = [...raw.warnings];
  const newAssets: Asset[] = [];
  for (const asset of normalized.assets) {
    if (existingAssets.some((a) => a.id === asset.id)) continue;
    if (!coveredByScope(asset, assessment.scope)) {
      asset.inScope = false;
      warnings.push(`asset ${label(asset)} is not covered by the scope: it was recorded as out of scope`);
    }
    newAssets.push(asset);
  }

  const incomingIds = new Set(normalized.findings.map((f) => f.id));
  const deduped = dedupe([...existing, ...normalized.findings], { now });
  const classified = classify(deduped.findings, { now });
  const merged = deduped.merged.reduce((n, m) => n + m.from.filter((id) => incomingIds.has(id)).length, 0);
  const created = classified.findings.filter((f) => !existingIds.has(f.id));
  const changed = classified.findings.filter((f) => existingIds.has(f.id) && touched(f, existing));

  const row: ImportRow = {
    id: newId("imp"),
    assessmentId: assessment.id,
    actor: who.sub,
    tool: input.tool,
    filename: input.filename ?? null,
    parsed: raw.findings.length,
    created: created.length,
    merged,
    assetsCreated: newAssets.length,
    warnings,
    at: now,
  };

  await db.transaction(async (tx) => {
    if (newAssets.length) await tx.insert(assets).values(newAssets.map(fromAsset));
    if (created.length) await tx.insert(findings).values(created.map(fromFinding));
    for (const f of changed) await tx.update(findings).set(fromFinding(f)).where(eq(findings.id, f.id));
    const newEvidence = [...created, ...changed].flatMap((f) => f.evidence.filter((e) => !existingEvidenceIds.has(e.id)).map((e) => fromEvidence(e, f.id)));
    if (newEvidence.length) await tx.insert(evidence).values(newEvidence).onConflictDoNothing();
    await tx.insert(imports).values(row);
    await record(tx, {
      assessmentId: assessment.id,
      actor: who.sub,
      action: "import",
      field: input.tool,
      ...(input.filename ? { from: input.filename } : {}),
      to: `${row.parsed} parsed, ${row.created} created, ${row.merged} merged`,
      at: now,
    });
  });

  return { ...toImport(row), unmapped: classified.unmapped, notes: classified.notes };
}

function label(asset: Asset): string {
  const where = asset.url ?? asset.host;
  return where && where !== asset.name ? `${asset.name} (${where})` : asset.name;
}

/** Did dedupe or classify change an existing finding? Compared on what they can touch. */
function touched(after: Finding, existing: Finding[]): boolean {
  const before = existing.find((f) => f.id === after.id);
  if (!before) return true;
  const view = (f: Finding) => JSON.stringify([f.sources, f.evidence.map((e) => e.id), f.risk, f.mappings, f.scope, f.impact, f.fix, f.phase, f.title]);
  return view(before) !== view(after);
}

export async function listImports(db: Db, assessmentId: string): Promise<ImportOut[]> {
  const rows = await db.select().from(imports).where(eq(imports.assessmentId, assessmentId)).orderBy(desc(imports.at), desc(imports.id));
  return rows.map(toImport);
}
