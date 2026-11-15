import { PHASES, PHASE_DETAILS, SEVERITIES, SEVERITY_LABELS, assetLabel, phaseNumber, type Asset } from "@retest/schema";
import type { CoverageRow, Report, ReportFinding } from "./model.js";

/**
 * The two documents as markdown, rendered from the report model. The technical report is for the
 * people who fix things: every finding, grouped by asset, the seven fields in the roadmap's order,
 * whether a person has verified it, and only evidence that has been redacted. The executive summary
 * is for the people who decide: the totals, the top risks, the trend and what the coverage hides.
 */

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function riskLine(f: ReportFinding): string {
  const parts: string[] = [f.risk.cvss ? `${f.risk.severity}, CVSS ${f.risk.cvss.baseScore} (${f.risk.cvss.vector})` : f.risk.severity];
  if (f.risk.likelihood) parts.push(`likelihood ${f.risk.likelihood}`);
  if (f.risk.impact) parts.push(`impact ${f.risk.impact}`);
  return parts.join("; ");
}

function mappingsLine(f: ReportFinding): string {
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

function retestLine(f: ReportFinding): string {
  if (!f.retest) return "Not retested yet.";
  const when = f.retest.testedAt ? ` on ${f.retest.testedAt.slice(0, 10)}` : "";
  return `${f.retest.outcome}${when}${f.retest.notes ? `: ${f.retest.notes}` : ""}`;
}

/** A code fence long enough not to be closed by the content. */
function fence(content: string): string {
  const longest = Math.max(2, ...[...content.matchAll(/`+/g)].map((m) => m[0].length));
  const ticks = "`".repeat(longest + 1);
  return `${ticks}\n${content.replace(/\s+$/, "")}\n${ticks}`;
}

/** One line on whether a person has checked it, under every finding's title. */
export function verifiedLine(f: ReportFinding): string {
  if (f.status === "false-positive") return "Not a finding: a person checked it and found it false.";
  if (f.verified) return `Verified: a person took it to ${PHASE_DETAILS[f.phase].label.toLowerCase()}.`;
  return "Not verified: a scanner reported it and nobody has checked it yet.";
}

function findingSection(f: ReportFinding): string {
  const redacted = f.evidence.filter((e) => e.redacted);
  const held = f.evidence.length - redacted.length;
  const lines = [`### ${f.title}`, "", `_${verifiedLine(f)}_`, "", `**Asset and scope:** ${f.scope}`, "", `**Impact:** ${f.impact}`, "", "**Evidence:**", ""];
  for (const e of redacted) {
    lines.push(`${e.title ? `${e.title} ` : ""}(${e.kind}${e.capturedAt ? `, ${e.capturedAt.slice(0, 10)}` : ""})`, "", fence(e.content), "");
  }
  if (held) lines.push(`_${plural(held, "piece")} of evidence not yet redacted, not shown._`, "");
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

export const STATE_WORDS: Record<CoverageRow["state"], string> = {
  found: "Findings",
  clean: "Looked, nothing found",
  "not-tested": "Not tested",
};

function coverageTable(rows: CoverageRow[], lookedHeader: string): string[] {
  return [
    `| Category | Findings | Open | Verified | ${lookedHeader} | Result |`,
    "| --- | --- | --- | --- | --- | --- |",
    ...rows.map((r) => `| ${r.id} ${r.name} | ${r.findings} | ${r.open} | ${r.verified} | ${r.lookedBy.length ? r.lookedBy.join(", ") : "none"} | ${STATE_WORDS[r.state]} |`),
  ];
}

export function coverageSection(report: Report): string[] {
  const { toolsRun, owasp, asvs } = report.coverage;
  return [
    "## Coverage",
    "",
    `Tools run: ${toolsRun.length ? toolsRun.join(", ") : "none"}.`,
    "",
    "### OWASP Top 10 2021",
    "",
    "A category counts as looked at when a tool that has rules for it ran. That means some of its issues were checked, not all of them. No scanner tests A04 Insecure Design.",
    "",
    ...coverageTable(owasp, "Looked for by"),
    "",
    "### ASVS 4.0.3 chapters",
    "",
    "A scanner can show a requirement failing; it cannot show a chapter passing. A chapter with no finding has not been verified, only not failed.",
    "",
    ...coverageTable(asvs, "Found by"),
    "",
  ];
}

function header(report: Report, kind: string): string[] {
  const a = report.assessment;
  const scope = a.scope;
  return [
    `# ${a.name}${kind}`,
    "",
    `${a.client ? `Client: ${a.client}. ` : ""}Authorised by ${scope.authorizedBy}${scope.authorizedAt ? ` on ${scope.authorizedAt.slice(0, 10)}` : ""}. Targets: ${scope.targets.join(", ")}.${scope.exclusions.length ? ` Excluded: ${scope.exclusions.join(", ")}.` : ""}`,
    "",
  ];
}

export function technicalMarkdown(report: Report): string {
  const c = report.counts;
  const out = [
    ...header(report, ""),
    "Technical report. One section per asset, one entry per finding, most severe first.",
    "",
    `Generated ${report.generatedAt.slice(0, 10)}. ${plural(c.findings, "finding")} on ${plural(c.assets, "asset")}. ${c.verified} verified by a person; the rest are scanner output and are marked as such.`,
    "",
  ];
  for (const g of report.groups) {
    out.push(`## ${assetLabel(g.asset)}`, "", `${g.asset.kind}${g.asset.inScope ? "" : ", recorded as out of scope"}. ${plural(g.findings.length, "finding")}.`, "");
    for (const f of g.findings) out.push(findingSection(f));
  }
  out.push(...coverageSection(report));
  return out.join("\n");
}

function assetName(report: Report, id: string): string {
  const asset: Asset | undefined = report.groups.find((g) => g.asset.id === id)?.asset;
  return asset ? assetLabel(asset) : id;
}

export function topRiskLine(report: Report, f: ReportFinding, i: number): string {
  const facts = [f.risk.severity, ...(f.risk.cvss ? [String(f.risk.cvss.baseScore)] : []), f.verified ? "verified" : "not verified"];
  const business = f.risk.likelihood && f.risk.impact ? ` Business risk: likelihood ${f.risk.likelihood}, impact ${f.risk.impact}.` : "";
  return `${i + 1}. **${f.title}** (${facts.join(", ")}) on ${assetName(report, f.assetId)}, ${f.scope}. ${f.impact}${business}`;
}

export function summaryMarkdown(report: Report): string {
  const c = report.counts;
  const a = report.assessment;
  const notTested = report.coverage.owasp.filter((r) => r.state === "not-tested");
  const out = [
    ...header(report, ": executive summary"),
    `${plural(c.findings, "finding")} on ${plural(c.assets, "asset")}: ${c.open} open, ${c.closed} closed, ${plural(c.falsePositive, "false positive")}, ${c.acceptedRisk} accepted. ${c.verified} of ${c.findings} findings verified by a person.`,
    "",
    `Phase: ${phaseNumber(a.phase)} of 6, ${PHASE_DETAILS[a.phase].label}. Status: ${a.status}.`,
    "",
  ];
  if (report.unverifiedSerious) {
    out.push(`${plural(report.unverifiedSerious, "high or critical finding is", "high or critical findings are")} still a scanner's claim. Read them as "to be checked", not as proven.`, "");
  }
  out.push(
    "## By severity",
    "",
    "False positives are left out.",
    "",
    "| Severity | Findings |",
    "| --- | --- |",
    ...[...SEVERITIES].reverse().map((s) => `| ${SEVERITY_LABELS[s]} | ${c.bySeverity[s]} |`),
    "",
    "## Top risks",
    "",
  );
  if (!report.topRisks.length) out.push("_No open finding above informational._", "");
  report.topRisks.forEach((f, i) => out.push(topRiskLine(report, f, i)));
  out.push(
    "",
    "## Severity and business risk",
    "",
    "Severity here is the CVSS base score: how bad the flaw is anywhere it appears. It does not know what the asset holds or who can reach it. Where the assessor has rated likelihood and impact for this business, the top risks show both, and that is the order to fix in.",
    "",
    "## Trend",
    "",
  );
  if (!report.trend.length) out.push("_Nothing imported yet._", "");
  else {
    out.push("| Day | Found | Closed | Set aside | Reopened | Open at end of day |", "| --- | --- | --- | --- | --- | --- |");
    for (const d of report.trend) out.push(`| ${d.day} | ${d.found} | ${d.closed} | ${d.setAside} | ${d.reopened} | ${d.open} |`);
    out.push("");
  }
  out.push(
    "## Coverage",
    "",
    `${10 - notTested.length} of the 10 OWASP Top 10 categories were looked at by the tools that ran (${report.coverage.toolsRun.join(", ") || "none"}).${notTested.length ? ` Not tested: ${notTested.map((r) => `${r.id} ${r.name}`).join(", ")}.` : ""} An empty category is not a clean bill of health; the technical report has the full matrix.`,
    "",
    "## By phase",
    "",
    "| Phase | Findings |",
    "| --- | --- |",
    ...PHASES.map((p) => `| ${phaseNumber(p)}. ${PHASE_DETAILS[p].label} | ${c.byPhase[p]} |`),
    "",
  );
  return out.join("\n");
}
