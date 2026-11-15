import { asc, eq, inArray } from "drizzle-orm";
import { assets, evidence, findings, type AssessmentRow, type Db } from "../db/index.js";
import { buildReport, type Report } from "../report/model.js";
import { summaryMarkdown, technicalMarkdown } from "../report/markdown.js";
import { toAssessment, toAsset, toFinding } from "../rows.js";
import { listAudit } from "./audit.js";
import { listImports } from "./imports.js";

/**
 * The reports of one assessment. The rows are read once and turned into a report model by pure
 * functions in `report/`; the JSON route, the two markdown routes and the demo all come from that
 * one model, so the technical report and the summary cannot disagree.
 */
export async function reportModel(db: Db, assessment: AssessmentRow, now = new Date()): Promise<Report> {
  const assetRows = await db.select().from(assets).where(eq(assets.assessmentId, assessment.id)).orderBy(asc(assets.name), asc(assets.id));
  const findingRows = await db.select().from(findings).where(eq(findings.assessmentId, assessment.id));
  const evidenceRows = findingRows.length ? await db.select().from(evidence).where(inArray(evidence.findingId, findingRows.map((f) => f.id))).orderBy(asc(evidence.id)) : [];
  const [importList, audit] = await Promise.all([listImports(db, assessment.id), listAudit(db, assessment.id)]);
  return buildReport({
    assessment: toAssessment(assessment),
    assets: assetRows.map(toAsset),
    findings: findingRows.map((f) => toFinding(f, evidenceRows.filter((e) => e.findingId === f.id))),
    imports: importList,
    audit,
    generatedAt: now.toISOString(),
  });
}

export async function technicalReport(db: Db, assessment: AssessmentRow): Promise<string> {
  return technicalMarkdown(await reportModel(db, assessment));
}

export async function executiveSummary(db: Db, assessment: AssessmentRow): Promise<string> {
  return summaryMarkdown(await reportModel(db, assessment));
}
