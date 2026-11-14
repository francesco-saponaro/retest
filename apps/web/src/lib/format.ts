import { PHASES, PHASE_DETAILS, SEVERITIES, SEVERITY_LABELS, isPhaseAfter, nextPhase, type Phase, type Scope, type Severity } from "@retest/schema";
import type { AuditLine, FindingDetail, FindingSummary, Totals } from "../api/client.js";

/** Critical first, the way a report lists them. */
export const REPORT_ORDER: readonly Severity[] = [...SEVERITIES].reverse();

/** "3 of 6 · Vulnerability assessment". */
export function phaseLine(phase: Phase): string {
  return `${PHASE_DETAILS[phase].number} of ${PHASES.length} · ${PHASE_DETAILS[phase].label}`;
}

const DAY = 24 * 60 * 60 * 1000;

/** "today", "yesterday", "3 days ago" up to a week, then the date. Days are counted on the calendar, in UTC. */
export function relativeDay(iso: string, now = new Date()): string {
  const then = new Date(iso);
  const days = Math.floor(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) / DAY) - Math.floor(Date.UTC(then.getUTCFullYear(), then.getUTCMonth(), then.getUTCDate()) / DAY);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days <= 7) return `${days} days ago`;
  return isoDate(iso);
}

/** "today 19:52", "yesterday 18:00", then the date; the clock in the reader's own zone. */
export function relativeTime(iso: string, now = new Date()): string {
  const day = relativeDay(iso, now);
  if (day !== "today" && day !== "yesterday") return day;
  const d = new Date(iso);
  return `${day} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

/** The date part of an ISO timestamp, in UTC. */
export function isoDate(iso: string): string {
  return iso.slice(0, 10);
}

/** The findings that reached validation or a later phase: the ones somebody, not a scanner, has looked at. */
export function verifiedCount(totals: Totals): number {
  return totals.byPhase.validation + totals.byPhase.risk + totals.byPhase.remediation;
}

/** "5 targets, no exclusions · authorised by francesco on 2026-11-10". */
export function scopeLine(scope: Scope): string {
  const exclusions = scope.exclusions.length === 0 ? "no exclusions" : count(scope.exclusions.length, "exclusion");
  const when = scope.authorizedAt ? ` on ${isoDate(scope.authorizedAt)}` : "";
  return `${count(scope.targets.length, "target")}, ${exclusions} · authorised by ${scope.authorizedBy}${when}`;
}

/** "1 finding", "37 findings", "8 entries". */
export function count(n: number, noun: string): string {
  if (n === 1) return `1 ${noun}`;
  const plural = /[^aeiou]y$/.test(noun) ? `${noun.slice(0, -1)}ies` : `${noun}s`;
  return `${n} ${plural}`;
}

/** The one line under an assessment's title: how much of it is still only what a scanner said. */
export function findingLine(totals: Totals): string {
  const { findings, assets } = totals;
  if (findings === 0) return assets === 0 ? "No findings and no assets yet: nothing has been imported." : `No findings yet on ${count(assets, "asset")}: nothing has been imported.`;
  const verified = verifiedCount(totals);
  const head = `${count(findings, "finding")} on ${count(assets, "asset")}`;
  if (verified === 0) return `${head}, and all ${findings} are still what a scanner said: none has reached validation.`;
  if (verified === findings) return `${head}; all of it verified.`;
  return `${head}; ${verified} verified, ${findings - verified} still what a scanner said.`;
}

/** What went wrong, in one line, whatever was thrown. */
export function messageOf(error: unknown): string {
  if (error instanceof Error) return error.message;
  return typeof error === "string" ? error : "unknown error";
}

/** The phase in one word, for a table cell. */
export const PHASE_SHORT: Record<Phase, string> = {
  scope: "Scope",
  recon: "Recon",
  assessment: "Assessment",
  validation: "Validation",
  risk: "Risk",
  remediation: "Remediation",
};

export function shortPhase(phase: Phase): string {
  return PHASE_SHORT[phase];
}

/** True once a person, not a scanner, has looked at the finding: phase 4 or later. */
export function isVerified(phase: Phase): boolean {
  return phase === "validation" || isPhaseAfter(phase, "validation");
}

/** "2 critical, 1 high, 1 medium": the non-zero severities of these findings, most severe first. */
function severityParts(items: Pick<FindingSummary, "risk">[]): string {
  const by = new Map<Severity, number>();
  for (const f of items) by.set(f.risk.severity, (by.get(f.risk.severity) ?? 0) + 1);
  return REPORT_ORDER.filter((s) => by.has(s) && s !== "info" && s !== "low")
    .map((s) => `${by.get(s)} ${s}`)
    .join(", ");
}

/**
 * The one line over the findings table, computed from the rows on screen: how many of the
 * assessment's findings the filters left, which of them are critical or high, and whether any has
 * been validated yet. `all` is the assessment's count, `matched` the filters' count, `items` the page.
 */
export function findingsLine(page: { all: number; matched: number; items: Pick<FindingSummary, "risk" | "phase">[]; filtered: boolean }): string {
  const { all, matched, items, filtered } = page;
  if (all === 0 && !filtered) return "No findings yet: nothing has been imported.";
  if (items.length === 0) return `0 of ${all} findings match.`;
  if (items.length < matched) return `The first ${items.length} of ${matched} findings; narrow them with the filters.`;
  const head = filtered ? `${matched} of ${all} findings match` : count(all, "finding");
  const parts = severityParts(items);
  const verified = items.filter((f) => isVerified(f.phase)).length;
  const tail = verified === 0 ? "none has reached validation" : `${verified} verified`;
  return `${head}${parts ? `: ${parts}` : ""}; ${tail}.`;
}

/** "nuclei and zap", "trivy", "nmap, nuclei and zap". */
export function toolList(tools: readonly string[]): string {
  const unique = [...new Set(tools)];
  if (unique.length <= 1) return unique[0] ?? "nobody";
  return `${unique.slice(0, -1).join(", ")} and ${unique[unique.length - 1]}`;
}

/** The one line under a finding's title: where it came from, and whether anybody has looked at it. */
export function findingState(f: Pick<FindingDetail, "risk" | "asset" | "sources" | "createdAt" | "phase" | "status" | "falsePositiveReason">, now = new Date()): string {
  const head = `${SEVERITY_LABELS[f.risk.severity]} on ${f.asset.name}, reported by ${toolList(f.sources.map((s) => s.tool))} ${relativeTime(f.createdAt, now)}.`;
  if (f.status === "false-positive") return `${head} Marked a false positive${f.falsePositiveReason ? `: ${f.falsePositiveReason.replace(/\.\s*$/, "")}` : ""}.`;
  if (f.status === "accepted-risk") return `${head} The risk has been accepted.`;
  if (f.status === "closed") return `${head} Closed: the retest found it fixed.`;
  switch (f.phase) {
    case "validation":
      return `${head} Being validated.`;
    case "risk":
      return `${head} Validated; being rated and written up.`;
    case "remediation":
      return `${head} Validated; waiting on the fix and the retest.`;
    default:
      return `${head} Still what a scanner said: nobody has validated it.`;
  }
}

/**
 * A finding's title as the page's headline: whole when it is short, the part before the colon
 * when a tool wrote "CVE-… in package: what it is", else cut at a word. The whole title is the
 * first of the seven fields, so nothing is lost; the headline only has to fit two lines on a phone.
 */
export function headline(title: string, max = 52): string {
  if (title.length <= max) return title;
  const colon = title.indexOf(": ");
  if (colon >= 12 && colon <= max) return title.slice(0, colon);
  const cut = title.slice(0, max - 1);
  const space = cut.lastIndexOf(" ");
  return `${(space >= 24 ? cut.slice(0, space) : cut).replace(/[\s:,;-]+$/, "")}…`;
}

/** The phase after this one, with the words for the button that moves there; null at the end. */
export function nextStep(phase: Phase): { phase: Phase; label: string } | null {
  const next = nextPhase(phase);
  return next ? { phase: next, label: `Move to ${PHASE_DETAILS[next].label.toLowerCase().split(" / ")[0]}` } : null;
}

const phaseWords = (p: string | null) => (p && p in PHASE_DETAILS ? PHASE_DETAILS[p as Phase].label.toLowerCase() : (p ?? "nowhere"));

/**
 * One audit line as a sentence without its subject, so a screen can put the actor and, for a
 * finding's line, the finding's name in front of it: "moved it from vulnerability assessment to
 * validation / exploitation", "imported nmap/juice-shop.xml with nmap: 4 parsed, 4 created, 0 merged".
 */
export function auditSentence(l: Pick<AuditLine, "action" | "field" | "from" | "to" | "findingId">): string {
  const it = l.findingId ? "it" : "the assessment";
  switch (l.action) {
    case "import":
      return `imported ${l.from ? `${l.from} with ${l.field}` : `a ${l.field} file`}: ${l.to ?? ""}`.trim();
    case "phase":
      return `moved ${it} from ${phaseWords(l.from)} to ${phaseWords(l.to)}`;
    case "retest":
      return `retested ${it}: ${(l.to ?? "pending").replace("-", " ")}`;
    case "status":
      if (!l.findingId) return `set the assessment ${l.to ?? ""}`.trim();
      switch (l.to) {
        case "false-positive":
          return "marked it a false positive";
        case "accepted-risk":
          return "accepted the risk";
        case "closed":
          return "closed it";
        case "open":
          return "reopened it";
        default:
          return `set it ${l.to ?? ""}`.trim();
      }
  }
}

/** "16 entries: 6 imports, 7 phase changes, 2 status changes, 1 retest; newest first." */
export function historyLine(lines: Pick<AuditLine, "action">[]): string {
  if (lines.length === 0) return "Nothing has happened yet.";
  const by = new Map<AuditLine["action"], number>();
  for (const l of lines) by.set(l.action, (by.get(l.action) ?? 0) + 1);
  const nouns: Record<AuditLine["action"], string> = { import: "import", phase: "phase change", status: "status change", retest: "retest" };
  const parts = (["import", "phase", "status", "retest"] as const).filter((a) => by.has(a)).map((a) => count(by.get(a)!, nouns[a]));
  return `${count(lines.length, "entry")}: ${parts.join(", ")}${lines.length > 1 ? "; newest first" : ""}.`;
}
