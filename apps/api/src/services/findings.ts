import {
  EvidenceKindSchema,
  EvidenceSchema,
  FindingSchema,
  FindingStatusSchema,
  MappingsSchema,
  OwaspTop10IdSchema,
  PhaseSchema,
  RiskSchema,
  SEVERITIES,
  SeveritySchema,
  ToolSchema,
  type Asset,
  type Evidence,
  type Finding,
  type Phase,
} from "@retest/schema";
import { classify } from "@retest/parsers";
import { and, asc, count, desc, eq, ilike, inArray, or, sql, type SQL } from "drizzle-orm";
import { z } from "zod";
import type { Principal } from "../auth.js";
import { assets, evidence, findings, type AssessmentRow, type AssetRow, type Db, type EvidenceRow, type FindingRow } from "../db/index.js";
import { HttpError, invalid, newId } from "../http.js";
import { fromEvidence, fromFinding, toAsset, toEvidence, toFinding, toFindingSummary, type FindingSummary } from "../rows.js";
import { loadAssessment } from "./assessments.js";
import { record } from "./audit.js";

/**
 * A finding made by hand: the seven fields minus the retest, which cannot exist yet. The status
 * is always `open` at creation; the phase defaults to validation, because a person who writes a
 * finding has usually just confirmed it. Sources, status and retest are set by the workflow.
 */
export const NewFindingSchema = z.strictObject({
  title: z.string().min(1).max(200),
  assetId: z.string().min(1),
  scope: z.string().min(1).max(500),
  impact: z.string().min(1),
  fix: z.string().min(1),
  risk: RiskSchema,
  phase: PhaseSchema.default("validation"),
  mappings: MappingsSchema.partial().optional(),
  evidence: z.array(EvidenceSchema.omit({ id: true, findingId: true })).default([]),
});

export const FindingPatchSchema = z.strictObject({
  title: z.string().min(1).max(200).optional(),
  assetId: z.string().min(1).optional(),
  scope: z.string().min(1).max(500).optional(),
  impact: z.string().min(1).optional(),
  fix: z.string().min(1).optional(),
  risk: RiskSchema.optional(),
  mappings: MappingsSchema.partial().optional(),
});

export const FindingPhaseSchema = z.strictObject({ phase: PhaseSchema, reason: z.string().min(1).max(2000).optional() });

export const NewEvidenceSchema = EvidenceSchema.omit({ id: true, findingId: true }).strict();
export const EvidenceQuerySchema = z.object({ kind: EvidenceKindSchema.default("note"), title: z.string().min(1).max(200).optional() });
export const EvidencePatchSchema = z
  .strictObject({ title: z.string().min(1).max(200).optional(), content: z.string().min(1).optional(), redacted: z.boolean().optional() })
  .refine((p) => Object.keys(p).length > 0, { message: "nothing to change", when: (payload) => payload.issues.length === 0 });

const list = <T extends string>(item: z.ZodType<T, string>) =>
  z
    .string()
    .transform((s) => s.split(",").map((x) => x.trim()).filter(Boolean))
    .pipe(z.array(item).min(1))
    .optional();

/** The filters of the findings table. Several values of one filter are a comma-separated list and mean "any of". */
export const FindingsQuerySchema = z.object({
  severity: list(SeveritySchema),
  phase: list(PhaseSchema),
  status: list(FindingStatusSchema),
  tool: list(ToolSchema),
  owasp: list(OwaspTop10IdSchema),
  assetId: z.string().min(1).optional(),
  /** Matched against the title and the scope, case-insensitively. */
  q: z.string().min(1).max(200).optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
  offset: z.coerce.number().int().min(0).default(0),
});

export type FindingsQuery = z.infer<typeof FindingsQuerySchema>;

export interface FindingDetail extends Finding {
  asset: Asset;
}

/** A finding the caller may see, through its assessment, or a 404. */
export async function requireFinding(db: Db, id: string, who: Principal): Promise<{ finding: FindingRow; assessment: AssessmentRow }> {
  const [finding] = await db.select().from(findings).where(eq(findings.id, id)).limit(1);
  const assessment = finding && (await loadAssessment(db, finding.assessmentId, who));
  if (!finding || !assessment) throw new HttpError(404, "finding not found");
  return { finding, assessment };
}

async function assetIn(db: Db, assessmentId: string, assetId: string): Promise<AssetRow | undefined> {
  const [row] = await db.select().from(assets).where(and(eq(assets.id, assetId), eq(assets.assessmentId, assessmentId))).limit(1);
  return row;
}

function requireOpen(assessment: AssessmentRow): void {
  if (assessment.status === "closed") throw new HttpError(409, "the assessment is closed");
}

export async function createFinding(db: Db, assessment: AssessmentRow, input: z.infer<typeof NewFindingSchema>, who: Principal, now = new Date()): Promise<Finding> {
  requireOpen(assessment);
  if (!(await assetIn(db, assessment.id, input.assetId))) {
    throw new HttpError(400, "invalid body", [{ path: "assetId", message: "not an asset of this assessment" }]);
  }
  const id = newId("f");
  const stamp = now.toISOString();
  const parsed = FindingSchema.safeParse({
    ...input,
    id,
    assessmentId: assessment.id,
    status: "open",
    sources: [{ tool: "manual", rawId: `manual-${who.sub}-${id.slice(2)}` }],
    mappings: { cwe: [], cve: [], owaspTop10: [], owaspApi: [], asvs: [], cis: [], ...input.mappings },
    evidence: input.evidence.map((e, i) => ({ ...e, id: `${id}-e${i + 1}`, findingId: id })),
    createdAt: stamp,
    updatedAt: stamp,
  });
  if (!parsed.success) invalid("body", parsed.error);
  // The same classification an import gets: the CWE fills the standards, a vector is checked against its score.
  const [finding] = classify([parsed.data], { now }).findings as [Finding];
  await db.transaction(async (tx) => {
    await tx.insert(findings).values(fromFinding(finding));
    if (finding.evidence.length) await tx.insert(evidence).values(finding.evidence.map((e) => fromEvidence(e, finding.id)));
  });
  return finding;
}

const SEVERITY_RANK = sql`case ${findings.severity} ${sql.join(
  SEVERITIES.map((s, i) => sql`when ${s} then ${i + 1}`),
  sql` `,
)} else 0 end`;

export function findingFilters(assessmentId: string, q: FindingsQuery): SQL {
  const where: (SQL | undefined)[] = [eq(findings.assessmentId, assessmentId)];
  if (q.severity) where.push(inArray(findings.severity, q.severity));
  if (q.phase) where.push(inArray(findings.phase, q.phase));
  if (q.status) where.push(inArray(findings.status, q.status));
  if (q.assetId) where.push(eq(findings.assetId, q.assetId));
  if (q.tool) where.push(or(...q.tool.map((tool) => sql`${findings.sources} @> ${JSON.stringify([{ tool }])}::jsonb`)));
  if (q.owasp) where.push(sql`${findings.mappings}->'owaspTop10' ?| array[${sql.join(q.owasp.map((o) => sql`${o}`), sql`, `)}]::text[]`);
  if (q.q) {
    const pattern = `%${q.q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    where.push(or(ilike(findings.title, pattern), ilike(findings.scope, pattern)));
  }
  return and(...where)!;
}

export async function listFindings(db: Db, assessmentId: string, q: FindingsQuery): Promise<{ items: FindingSummary[]; total: number }> {
  const where = findingFilters(assessmentId, q);
  // Written out by hand: in a single-table select the query builder drops the table qualifiers, and
  // `"finding_id" = "id"` inside the subquery would compare evidence with itself.
  const evidenceCount = sql<number>`(select count(*)::int from evidence e where e.finding_id = findings.id)`;
  const [rows, [total]] = await Promise.all([
    db
      .select({ row: findings, evidenceCount })
      .from(findings)
      .where(where)
      .orderBy(desc(SEVERITY_RANK), asc(findings.title), asc(findings.id))
      .limit(q.limit)
      .offset(q.offset),
    db.select({ n: count() }).from(findings).where(where),
  ]);
  return { items: rows.map((r) => toFindingSummary(r.row, r.evidenceCount)), total: total?.n ?? 0 };
}

export async function evidenceOf(db: Db, findingId: string): Promise<EvidenceRow[]> {
  return db.select().from(evidence).where(eq(evidence.findingId, findingId)).orderBy(asc(evidence.id));
}

export async function findingDetail(db: Db, row: FindingRow): Promise<FindingDetail> {
  const [ev, asset] = await Promise.all([evidenceOf(db, row.id), assetIn(db, row.assessmentId, row.assetId)]);
  return { ...toFinding(row, ev), asset: toAsset(asset!) };
}

/** Apply the patch to the whole finding and run it through the schema again, so every rule still holds. */
export async function updateFinding(db: Db, row: FindingRow, patch: z.infer<typeof FindingPatchSchema>, now = new Date()): Promise<Finding> {
  if (patch.assetId !== undefined && !(await assetIn(db, row.assessmentId, patch.assetId))) {
    throw new HttpError(400, "invalid body", [{ path: "assetId", message: "not an asset of this assessment" }]);
  }
  const current = toFinding(row, []);
  const parsed = FindingSchema.safeParse({
    ...current,
    ...patch,
    ...(patch.mappings ? { mappings: { ...current.mappings, ...patch.mappings } } : {}),
    updatedAt: now.toISOString(),
  });
  if (!parsed.success) invalid("body", parsed.error);
  const [updated] = classify([parsed.data], { now }).findings as [Finding];
  await db.update(findings).set(fromFinding(updated)).where(eq(findings.id, row.id));
  return toFinding((await db.select().from(findings).where(eq(findings.id, row.id)))[0]!, await evidenceOf(db, row.id));
}

export async function setFindingPhase(db: Db, row: FindingRow, phase: Phase, who: Principal, reason?: string, now = new Date()): Promise<Finding> {
  if (row.phase !== phase) {
    await db.transaction(async (tx) => {
      await tx.update(findings).set({ phase, updatedAt: now }).where(eq(findings.id, row.id));
      await record(tx, { assessmentId: row.assessmentId, findingId: row.id, actor: who.sub, action: "phase", field: "phase", from: row.phase, to: phase, ...(reason ? { reason } : {}), at: now });
    });
  }
  const [updated] = await db.select().from(findings).where(eq(findings.id, row.id));
  return toFinding(updated!, await evidenceOf(db, row.id));
}

export async function addEvidence(db: Db, row: FindingRow, input: z.infer<typeof NewEvidenceSchema>, now = new Date()): Promise<Evidence> {
  const parsed = EvidenceSchema.safeParse({ ...input, id: newId("ev"), findingId: row.id });
  if (!parsed.success) invalid("body", parsed.error);
  const stored = fromEvidence(parsed.data, row.id);
  await db.transaction(async (tx) => {
    await tx.insert(evidence).values(stored);
    await tx.update(findings).set({ updatedAt: now }).where(eq(findings.id, row.id));
  });
  return toEvidence(stored);
}

/** A piece of evidence the caller may see, through its finding's assessment, or a 404. */
export async function requireEvidence(db: Db, id: string, who: Principal): Promise<{ evidence: EvidenceRow; finding: FindingRow }> {
  const [ev] = await db.select().from(evidence).where(eq(evidence.id, id)).limit(1);
  if (!ev) throw new HttpError(404, "evidence not found");
  try {
    const { finding } = await requireFinding(db, ev.findingId, who);
    return { evidence: ev, finding };
  } catch {
    throw new HttpError(404, "evidence not found");
  }
}

export async function updateEvidence(db: Db, row: EvidenceRow, patch: z.infer<typeof EvidencePatchSchema>): Promise<Evidence> {
  const parsed = EvidenceSchema.safeParse({ ...toEvidence(row), ...patch });
  if (!parsed.success) invalid("body", parsed.error);
  await db.update(evidence).set(fromEvidence(parsed.data, row.findingId)).where(eq(evidence.id, row.id));
  return parsed.data;
}
