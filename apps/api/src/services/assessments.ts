import {
  AssessmentStatusSchema,
  FINDING_STATUSES,
  PHASES,
  PhaseSchema,
  SEVERITIES,
  ScopeSchema,
  type AssessmentStatus,
  type FindingStatus,
  type Phase,
  type Severity,
} from "@retest/schema";
import { count, desc, eq } from "drizzle-orm";
import { z } from "zod";
import type { Principal } from "../auth.js";
import { assessments, assets, findings, type AssessmentRow, type Db } from "../db/index.js";
import { HttpError, newId } from "../http.js";
import { toAssessment, type AssessmentOut } from "../rows.js";
import { record } from "./audit.js";

/** What a client may send to create one. The id, the owner, the phase and the status are the server's. */
export const NewAssessmentSchema = z.strictObject({
  name: z.string().min(1).max(200),
  client: z.string().min(1).max(200).optional(),
  scope: ScopeSchema,
});

export const AssessmentPatchSchema = z
  .strictObject({
    name: z.string().min(1).max(200).optional(),
    client: z.string().min(1).max(200).nullable().optional(),
    scope: ScopeSchema.optional(),
  })
  .refine((p) => Object.keys(p).length > 0, { message: "nothing to change", when: (payload) => payload.issues.length === 0 });

export const PhaseChangeSchema = z.strictObject({ phase: PhaseSchema, reason: z.string().min(1).max(2000).optional() });
export const StatusChangeSchema = z.strictObject({ status: AssessmentStatusSchema, reason: z.string().min(1).max(2000).optional() });

/**
 * Who may see an assessment: its owner, or an admin. Every row under an assessment (assets,
 * findings, evidence, audit lines, imports) is reached through this check, so there is no route
 * on which an id alone opens somebody else's data.
 */
export function canAccess(row: AssessmentRow, who: Principal): boolean {
  return who.role === "admin" || row.ownerId === who.sub;
}

/** The row, or undefined when it does not exist or the caller may not see it. The two cases look the same to the client. */
export async function loadAssessment(db: Db, id: string, who: Principal): Promise<AssessmentRow | undefined> {
  const [row] = await db.select().from(assessments).where(eq(assessments.id, id)).limit(1);
  return row && canAccess(row, who) ? row : undefined;
}

/** The row the caller may see, or a 404. */
export async function requireAssessment(db: Db, id: string, who: Principal): Promise<AssessmentRow> {
  const row = await loadAssessment(db, id, who);
  if (!row) throw new HttpError(404, "assessment not found");
  return row;
}

/** The id is the server's: random unless the caller is the seed, which may name it so that a demo link survives a reload. */
export async function createAssessment(db: Db, input: z.infer<typeof NewAssessmentSchema>, who: Principal, now = new Date(), id = newId("a")): Promise<AssessmentOut> {
  const row: AssessmentRow = {
    id,
    ownerId: who.sub,
    name: input.name,
    client: input.client ?? null,
    scope: input.scope,
    phase: "scope",
    status: "draft",
    createdAt: now,
    updatedAt: now,
  };
  await db.insert(assessments).values(row);
  return toAssessment(row);
}

export async function listAssessments(db: Db, who: Principal): Promise<AssessmentOut[]> {
  const rows = await db
    .select()
    .from(assessments)
    .where(who.role === "admin" ? undefined : eq(assessments.ownerId, who.sub))
    .orderBy(desc(assessments.createdAt), desc(assessments.id));
  return rows.map(toAssessment);
}

export interface Totals {
  findings: number;
  assets: number;
  bySeverity: Record<Severity, number>;
  byPhase: Record<Phase, number>;
  byStatus: Record<FindingStatus, number>;
}

export async function totals(db: Db, assessmentId: string): Promise<Totals> {
  const [[assetCount], rows] = await Promise.all([
    db.select({ n: count() }).from(assets).where(eq(assets.assessmentId, assessmentId)),
    db
      .select({ severity: findings.severity, phase: findings.phase, status: findings.status, n: count() })
      .from(findings)
      .where(eq(findings.assessmentId, assessmentId))
      .groupBy(findings.severity, findings.phase, findings.status),
  ]);
  const zero = <K extends string>(keys: readonly K[]) => Object.fromEntries(keys.map((k) => [k, 0])) as Record<K, number>;
  const t: Totals = { findings: 0, assets: assetCount?.n ?? 0, bySeverity: zero(SEVERITIES), byPhase: zero(PHASES), byStatus: zero(FINDING_STATUSES) };
  for (const r of rows) {
    t.findings += r.n;
    t.bySeverity[r.severity] += r.n;
    t.byPhase[r.phase] += r.n;
    t.byStatus[r.status] += r.n;
  }
  return t;
}

export async function updateAssessment(db: Db, row: AssessmentRow, patch: z.infer<typeof AssessmentPatchSchema>, now = new Date()): Promise<AssessmentOut> {
  const [updated] = await db
    .update(assessments)
    .set({
      ...(patch.name !== undefined ? { name: patch.name } : {}),
      ...(patch.client !== undefined ? { client: patch.client } : {}),
      ...(patch.scope !== undefined ? { scope: patch.scope } : {}),
      updatedAt: now,
    })
    .where(eq(assessments.id, row.id))
    .returning();
  return toAssessment(updated!);
}

export async function setAssessmentPhase(db: Db, row: AssessmentRow, phase: Phase, who: Principal, reason?: string, now = new Date()): Promise<AssessmentOut> {
  if (row.phase === phase) return toAssessment(row);
  const [updated] = await db.update(assessments).set({ phase, updatedAt: now }).where(eq(assessments.id, row.id)).returning();
  await record(db, { assessmentId: row.id, actor: who.sub, action: "phase", field: "phase", from: row.phase, to: phase, ...(reason ? { reason } : {}), at: now });
  return toAssessment(updated!);
}

export async function setAssessmentStatus(db: Db, row: AssessmentRow, status: AssessmentStatus, who: Principal, reason?: string, now = new Date()): Promise<AssessmentOut> {
  if (row.status === status) return toAssessment(row);
  const [updated] = await db.update(assessments).set({ status, updatedAt: now }).where(eq(assessments.id, row.id)).returning();
  await record(db, { assessmentId: row.id, actor: who.sub, action: "status", field: "status", from: row.status, to: status, ...(reason ? { reason } : {}), at: now });
  return toAssessment(updated!);
}

/** Everything under the assessment goes with it: the foreign keys cascade. */
export async function deleteAssessment(db: Db, row: AssessmentRow): Promise<void> {
  await db.delete(assessments).where(eq(assessments.id, row.id));
}
