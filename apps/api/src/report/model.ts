import {
  ASVS_V4_CHAPTERS,
  OWASP_TOP_10_2021,
  PHASES,
  SEVERITIES,
  TOOLS,
  compareSeverity,
  phaseNumber,
  toolsThatLookFor,
  type Asset,
  type Finding,
  type Phase,
  type Severity,
  type Tool,
} from "@retest/schema";
import type { AssessmentOut, AuditLine, ImportOut } from "../rows.js";

/**
 * Everything the two documents say, worked out once from the rows, with no database and no clock:
 * the markdown and the web screen both render this, so they cannot disagree, and the demo builds it
 * in the browser from the same functions.
 *
 * Two ideas run through it. A finding is verified only when a person has taken it to validation or
 * later and has not set it aside as false: the scanner suggests, the assessor proves. And a coverage
 * matrix with an empty cell must say why it is empty: a category where a tool looked and found
 * nothing is not the same as one nobody looked at.
 */

export interface ReportInput {
  assessment: AssessmentOut;
  assets: Asset[];
  findings: Finding[];
  imports: ImportOut[];
  audit: AuditLine[];
  /** When the report was made, an ISO date-time. Passed in so the same rows give the same report. */
  generatedAt: string;
}

export interface ReportFinding extends Finding {
  verified: boolean;
}

export interface ReportGroup {
  asset: Asset;
  findings: ReportFinding[];
}

export interface TrendDay {
  /** A calendar day in UTC, YYYY-MM-DD. */
  day: string;
  /** New findings the imports created that day. */
  found: number;
  /** Findings a retest closed. */
  closed: number;
  /** Findings marked false positive or accepted risk. */
  setAside: number;
  /** Findings taken back to open. */
  reopened: number;
  /** Open at the end of the day, counted from the first import. */
  open: number;
}

/** found: there are findings in it. clean: a tool that looks for it ran and found nothing. not-tested: nobody looked. */
export type CoverageState = "found" | "clean" | "not-tested";

export interface CoverageRow {
  id: string;
  name: string;
  /** Findings in this category, false positives left out. */
  findings: number;
  open: number;
  verified: number;
  /** The tools that ran and look for this category. For ASVS, the tools that found something in it. */
  lookedBy: Tool[];
  state: CoverageState;
}

export interface Report {
  assessment: AssessmentOut;
  generatedAt: string;
  counts: {
    findings: number;
    assets: number;
    open: number;
    closed: number;
    falsePositive: number;
    acceptedRisk: number;
    /** Taken to validation or later by a person and not a false positive. */
    verified: number;
    /** Open and still only a scanner's claim. */
    unverifiedOpen: number;
    /** Every finding except false positives, by severity. */
    bySeverity: Record<Severity, number>;
    byPhase: Record<Phase, number>;
  };
  groups: ReportGroup[];
  /** The open findings above informational, most severe first; verified before unverified at the same severity. At most five. */
  topRisks: ReportFinding[];
  /** Open high and critical findings nobody has verified yet: the number a manager should ask about. */
  unverifiedSerious: number;
  trend: TrendDay[];
  coverage: {
    toolsRun: Tool[];
    owasp: CoverageRow[];
    asvs: CoverageRow[];
  };
}

export function isVerified(f: Finding): boolean {
  return phaseNumber(f.phase) >= phaseNumber("validation") && f.status !== "false-positive";
}

function byRisk(a: ReportFinding, b: ReportFinding): number {
  return (
    compareSeverity(b.risk.severity, a.risk.severity) ||
    Number(b.verified) - Number(a.verified) ||
    (b.risk.cvss?.baseScore ?? 0) - (a.risk.cvss?.baseScore ?? 0) ||
    a.title.localeCompare(b.title) ||
    a.id.localeCompare(b.id)
  );
}

function bySeverityThenTitle(a: Finding, b: Finding): number {
  return compareSeverity(b.risk.severity, a.risk.severity) || a.title.localeCompare(b.title) || a.id.localeCompare(b.id);
}

const zero = <K extends string>(keys: readonly K[]) => Object.fromEntries(keys.map((k) => [k, 0])) as Record<K, number>;

const SET_ASIDE = new Set(["false-positive", "accepted-risk"]);

/** One row per day on which something was found or a finding changed status, oldest first. */
export function trend(imports: ImportOut[], audit: AuditLine[]): TrendDay[] {
  const days = new Map<string, TrendDay>();
  const day = (iso: string) => {
    const d = iso.slice(0, 10);
    let row = days.get(d);
    if (!row) {
      row = { day: d, found: 0, closed: 0, setAside: 0, reopened: 0, open: 0 };
      days.set(d, row);
    }
    return row;
  };
  for (const i of imports) if (i.created > 0) day(i.at).found += i.created;
  for (const l of audit) {
    if (!l.findingId || l.field !== "status") continue;
    if (l.from === "open" && l.to === "closed") day(l.at).closed += 1;
    else if (l.from === "open" && l.to && SET_ASIDE.has(l.to)) day(l.at).setAside += 1;
    else if (l.to === "open" && l.from !== "open") day(l.at).reopened += 1;
  }
  let open = 0;
  return [...days.values()]
    .sort((a, b) => a.day.localeCompare(b.day))
    .map((d) => {
      open += d.found + d.reopened - d.closed - d.setAside;
      return { ...d, open };
    });
}

function coverageRow(id: string, name: string, mine: ReportFinding[], lookedBy: Tool[]): CoverageRow {
  const state: CoverageState = mine.length ? "found" : lookedBy.length ? "clean" : "not-tested";
  return { id, name, findings: mine.length, open: mine.filter((f) => f.status === "open").length, verified: mine.filter((f) => f.verified).length, lookedBy, state };
}

export function buildReport(input: ReportInput): Report {
  const all: ReportFinding[] = input.findings.map((f) => ({ ...f, verified: isVerified(f) }));
  const real = all.filter((f) => f.status !== "false-positive");
  const open = all.filter((f) => f.status === "open");

  const bySeverity = zero(SEVERITIES);
  for (const f of real) bySeverity[f.risk.severity] += 1;
  const byPhase = zero(PHASES);
  for (const f of all) byPhase[f.phase] += 1;

  const assets = [...input.assets].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  const groups = assets
    .map((asset) => ({ asset, findings: all.filter((f) => f.assetId === asset.id).sort(bySeverityThenTitle) }))
    .filter((g) => g.findings.length > 0);

  const ran = new Set(input.imports.map((i) => i.tool));
  const toolsRun = TOOLS.filter((t) => t !== "manual" && ran.has(t));

  const owasp = OWASP_TOP_10_2021.map((c) => coverageRow(c.id, c.name, real.filter((f) => f.mappings.owaspTop10.includes(c.id)), toolsThatLookFor(c.id, toolsRun)));
  const asvs = ASVS_V4_CHAPTERS.map((c) => {
    const mine = real.filter((f) => f.mappings.asvs.includes(c.id));
    const foundBy = TOOLS.filter((t) => mine.some((f) => f.sources.some((s) => s.tool === t)));
    return coverageRow(c.id, c.name, mine, foundBy);
  });

  return {
    assessment: input.assessment,
    generatedAt: input.generatedAt,
    counts: {
      findings: all.length,
      assets: input.assets.length,
      open: open.length,
      closed: all.filter((f) => f.status === "closed").length,
      falsePositive: all.filter((f) => f.status === "false-positive").length,
      acceptedRisk: all.filter((f) => f.status === "accepted-risk").length,
      verified: all.filter((f) => f.verified).length,
      unverifiedOpen: open.filter((f) => !f.verified).length,
      bySeverity,
      byPhase,
    },
    groups,
    topRisks: open.filter((f) => f.risk.severity !== "info").sort(byRisk).slice(0, 5),
    unverifiedSerious: open.filter((f) => !f.verified && (f.risk.severity === "high" || f.risk.severity === "critical")).length,
    trend: trend(input.imports, input.audit),
    coverage: { toolsRun, owasp, asvs },
  };
}
