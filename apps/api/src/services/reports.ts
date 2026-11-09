import { PHASE_DETAILS, SEVERITIES, SEVERITY_LABELS, assetLabel, compareSeverity, phaseNumber, type Asset, type Finding, type Severity } from "@retest/schema";
import { asc, eq, inArray } from "drizzle-orm";
import { assets, evidence, findings, type AssessmentRow, type Db } from "../db/index.js";
import { toAsset, toFinding } from "../rows.js";
import { totals } from "./assessments.js";

/**
 * The two documents an assessment produces, as markdown. The technical report is for the people
 * who will fix things: every finding, grouped by asset, with the seven fields in the roadmap's
 * order and only the evidence that has been redacted. The executive summary is for the people
 * who decide: the totals, the top risks and where the work stands. Both are built from the same
 * rows, so they cannot disagree.
 */

interface Loaded {
  assets: Asset[];
  findings: Finding[];
}

async function load(db: Db, assessmentId: string): Promise<Loaded> {
  const assetRows = await db.select().from(assets).where(eq(assets.assessmentId, assessmentId)).orderBy(asc(assets.name), asc(assets.id));
  const findingRows = await db.select().from(findings).where(eq(findings.assessmentId, assessmentId));
  const evidenceRows = findingRows.length ? await db.select().from(evidence).where(inArray(evidence.findingId, findingRows.map((f) => f.id))).orderBy(asc(evidence.id)) : [];
  const all = findingRows.map((f) => toFinding(f, evidenceRows.filter((e) => e.findingId === f.id)));
  return { assets: assetRows.map(toAsset), findings: bySeverityThenTitle(all) };
}

function bySeverityThenTitle(list: Finding[]): Finding[] {
  return [...list].sort((a, b) => compareSeverity(b.risk.severity, a.risk.severity) || a.title.localeCompare(b.title) || a.id.localeCompare(b.id));
}

function riskLine(f: Finding): string {
  const parts: string[] = [f.risk.cvss ? `${f.risk.severity}, CVSS ${f.risk.cvss.baseScore} (${f.risk.cvss.vector})` : f.risk.severity];
  if (f.risk.likelihood) parts.push(`likelihood ${f.risk.likelihood}`);
  if (f.risk.impact) parts.push(`impact ${f.risk.impact}`);
  return parts.join("; ");
}

function mappingsLine(f: Finding): string {
  const m = f.mappings;
  const parts: string[] = [];
  if (m.owaspTop10.length) parts.push(`OWASP ${m.owaspTop10.join(", ")}`);
  if (m.owaspApi.length) parts.push(`OWASP API ${m.owaspApi.join(", ")}`);
  if (m.asvs.length) parts.push(`ASVS ${m.asvs.join(", ")}`);
  if (m.cis.length) parts.push(`CIS ${m.cis.join(", ")}`);
  if (m.cwe.length) parts.push(m.cwe.map((c) => `CWE-${c}`).join(", "));
  if (m.cve.length) parts.push(m.cve.join(", "));
  return parts.join("; ");
}

function retestLine(f: Finding): string {
  if (!f.retest) return "Not retested yet.";
  const when = f.retest.testedAt ? ` on ${f.retest.testedAt.slice(0, 10)}` : "";
  return `${f.retest.outcome}${when}${f.retest.notes ? `: ${f.retest.notes}` : ""}`;
}

function fence(content: string): string {
  const ticks = /```/.test(content) ? "````" : "```";
  return `${ticks}\n${content.replace(/\s+$/, "")}\n${ticks}`;
}

function findingSection(f: Finding): string {
  const redacted = f.evidence.filter((e) => e.redacted);
  const held = f.evidence.length - redacted.length;
  const lines = [
    `### ${f.title}`,
    "",
    `**Asset and scope:** ${f.scope}`,
    "",
    `**Impact:** ${f.impact}`,
    "",
    "**Evidence:**",
    "",
  ];
  for (const e of redacted) {
    lines.push(`${e.title ? `${e.title} ` : ""}(${e.kind}${e.capturedAt ? `, ${e.capturedAt.slice(0, 10)}` : ""})`, "", fence(e.content), "");
  }
  if (held) lines.push(`_${held} piece${held === 1 ? "" : "s"} of evidence not yet redacted, not shown._`, "");
  if (!f.evidence.length) lines.push("_None recorded._", "");
  lines.push(`**Risk:** ${riskLine(f)}`, "");
  const mapped = mappingsLine(f);
  if (mapped) lines.push(`Standards: ${mapped}`, "");
  lines.push(`**Fix:** ${f.fix}`, "", `**Retest:** ${retestLine(f)}`, "");
  const meta = [`Phase ${phaseNumber(f.phase)} (${PHASE_DETAILS[f.phase].label.toLowerCase()})`, `status ${f.status}`];
  if (f.falsePositiveReason) meta.push(`false positive because: ${f.falsePositiveReason}`);
  lines.push(`Sources: ${f.sources.map((s) => `${s.tool} ${s.rawId}`).join(", ")}. ${meta.join(", ")}.`, "");
  return lines.join("\n");
}

export async function technicalReport(db: Db, assessment: AssessmentRow): Promise<string> {
  const { assets: assetList, findings: all } = await load(db, assessment.id);
  const out = [
    `# ${assessment.name}`,
    "",
    "Technical report. One section per asset, one entry per finding, most severe first.",
    "",
    `${assessment.client ? `Client: ${assessment.client}. ` : ""}Authorised by ${assessment.scope.authorizedBy}${assessment.scope.authorizedAt ? ` on ${assessment.scope.authorizedAt.slice(0, 10)}` : ""}. Targets: ${assessment.scope.targets.join(", ")}.${assessment.scope.exclusions.length ? ` Excluded: ${assessment.scope.exclusions.join(", ")}.` : ""}`,
    "",
    `Generated ${new Date().toISOString().slice(0, 10)}. ${all.length} finding${all.length === 1 ? "" : "s"} on ${assetList.length} asset${assetList.length === 1 ? "" : "s"}.`,
    "",
  ];
  for (const asset of assetList) {
    const mine = all.filter((f) => f.assetId === asset.id);
    if (!mine.length) continue;
    out.push(`## ${assetLabel(asset)}`, "", `${asset.kind}${asset.inScope ? "" : ", recorded as out of scope"}. ${mine.length} finding${mine.length === 1 ? "" : "s"}.`, "");
    for (const f of mine) out.push(findingSection(f));
  }
  return out.join("\n");
}

export async function executiveSummary(db: Db, assessment: AssessmentRow): Promise<string> {
  const { assets: assetList, findings: all } = await load(db, assessment.id);
  const t = await totals(db, assessment.id);
  const open = all.filter((f) => f.status === "open");
  const validated = all.filter((f) => phaseNumber(f.phase) >= 4 && f.status !== "false-positive").length;
  const top = bySeverityThenTitle(open.filter((f) => f.risk.severity !== "info")).slice(0, 5);
  const out = [
    `# ${assessment.name}: executive summary`,
    "",
    `${all.length} findings on ${assetList.length} asset${assetList.length === 1 ? "" : "s"}, ${t.byStatus.open} open, ${t.byStatus.closed} closed, ${t.byStatus["false-positive"]} false positive${t.byStatus["false-positive"] === 1 ? "" : "s"}, ${t.byStatus["accepted-risk"]} accepted. ${validated} of ${all.length} findings validated.`,
    "",
    `Phase: ${phaseNumber(assessment.phase)} of 6, ${PHASE_DETAILS[assessment.phase]!.label}. Status: ${assessment.status}.`,
    "",
    "## By severity",
    "",
    "| Severity | Findings |",
    "| --- | --- |",
    ...[...SEVERITIES].reverse().map((s: Severity) => `| ${SEVERITY_LABELS[s]} | ${t.bySeverity[s]} |`),
    "",
    "## Top risks",
    "",
  ];
  if (!top.length) out.push("_No open finding above informational._", "");
  top.forEach((f, i) => {
    const asset = assetList.find((a) => a.id === f.assetId);
    out.push(`${i + 1}. **${f.title}** (${f.risk.severity}${f.risk.cvss ? `, ${f.risk.cvss.baseScore}` : ""}) on ${asset ? assetLabel(asset) : f.assetId}, ${f.scope}. ${f.impact}`);
  });
  out.push("", "## By phase", "", "| Phase | Findings |", "| --- | --- |");
  for (const phase of Object.keys(PHASE_DETAILS) as (keyof typeof PHASE_DETAILS)[]) {
    out.push(`| ${phaseNumber(phase)}. ${PHASE_DETAILS[phase].label} | ${t.byPhase[phase]} |`);
  }
  out.push("");
  return out.join("\n");
}
