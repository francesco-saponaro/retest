import { FindingSchema, baseScore, compareSeverity, isPhaseAfter, severityFromScore, type Evidence, type Finding, type Risk, type Source, type Tool } from "@retest/schema";
import { UNASSESSED_IMPACT, UNWRITTEN_FIX } from "./normalize.js";
import { cut } from "./text.js";

/**
 * Deduplication: the same weakness on the same asset, seen by several tools (or by one tool
 * twice), becomes one finding with several sources.
 *
 * "The same weakness" has to be said, not guessed. The fingerprint below says it in four ways,
 * in order: the CVE ids, when there are any (a CVE is one vulnerability wherever it is listed);
 * a table of the checks that different tools name differently for the same thing (a missing
 * header, a wildcard CORS policy); the CWE at the same place; and, when the tool gave neither a
 * CWE nor a CVE, the tool's own id at the same place, which only ever matches a re-import.
 * Findings on different assets never merge: a Semgrep hit in `routes/search.ts` and a ZAP alert
 * on `/rest/products/search` may well be the same bug, but proving it is validation, not parsing.
 */

interface SameWeakness {
  tool: Tool;
  match: RegExp;
  key: (m: RegExpExecArray) => string;
}

/** Checks that several tools run under different names. Keyed per asset, not per path: a header policy is a property of the site. */
const SAME_WEAKNESS: SameWeakness[] = [
  { tool: "nuclei", match: /^http-missing-security-headers:(.+)$/, key: (m) => `missing-header:${m[1]!.toLowerCase()}` },
  { tool: "zap", match: /^10038$/, key: () => "missing-header:content-security-policy" },
  { tool: "zap", match: /^10035$/, key: () => "missing-header:strict-transport-security" },
  { tool: "zap", match: /^10020$/, key: () => "missing-header:x-frame-options" },
  { tool: "zap", match: /^10021$/, key: () => "missing-header:x-content-type-options" },
  { tool: "zap", match: /^10063$/, key: () => "missing-header:permissions-policy" },
  { tool: "nuclei", match: /^cors-misconfig(?::(.+))?$/, key: (m) => `cors:${(m[1] ?? "arbitrary-origin").toLowerCase()}` },
  { tool: "zap", match: /^10098$/, key: () => "cors:arbitrary-origin" },
];

function aliasOf(source: Source): string | undefined {
  for (const rule of SAME_WEAKNESS) {
    if (rule.tool !== source.tool) continue;
    const m = rule.match.exec(source.rawId);
    if (m) return rule.key(m);
  }
  return undefined;
}

/** Lower case, query values dropped (`?q=apple` becomes `?q=`), whitespace trimmed. */
export function normalizeScope(scope: string): string {
  return scope.trim().toLowerCase().replace(/=([^&,\s]*)/g, "=");
}

/** `<assetId>|<weakness>`: two findings with the same fingerprint are one finding. */
export function fingerprint(f: Finding): string {
  const cves = [...new Set(f.mappings.cve)].sort();
  if (cves.length > 0) return `${f.assetId}|cve:${cves.join(",")}`;
  for (const source of f.sources) {
    const alias = aliasOf(source);
    if (alias) return `${f.assetId}|${alias}`;
  }
  const place = normalizeScope(f.scope);
  const cwes = [...new Set(f.mappings.cwe)].sort((a, b) => a - b);
  if (cwes.length > 0) return `${f.assetId}|cwe:${cwes.join(",")}@${place}`;
  const first = f.sources[0];
  return `${f.assetId}|${first ? `${first.tool}:${first.rawId}` : "unsourced"}@${place}`;
}

export interface DedupeOptions {
  /** The time to stamp on a finding that absorbed another. Defaults to now. */
  now?: Date;
}

export interface Merge {
  /** The finding that was kept. */
  into: string;
  /** The ids of the findings folded into it, in order. */
  from: string[];
}

export interface Deduped {
  findings: Finding[];
  merged: Merge[];
}

const SCOPE_MAX = 500;

function mergeScope(kept: string, other: string): string {
  if (kept === other || kept.includes(other)) return kept;
  if (other.includes(kept)) return other;
  return cut(`${kept}, ${other}`, SCOPE_MAX);
}

function mergeRisk(kept: Risk, other: Risk): Risk {
  if (kept.cvss && other.cvss) {
    return baseScore(other.cvss.vector) > baseScore(kept.cvss.vector) ? { ...kept, ...other } : kept;
  }
  if (other.cvss) return { ...kept, cvss: other.cvss, severity: severityFromScore(other.cvss.baseScore) };
  if (kept.cvss) return kept;
  const risk: Risk = { ...kept };
  if (compareSeverity(other.severity, kept.severity) > 0) risk.severity = other.severity;
  if (!risk.likelihood && other.likelihood) risk.likelihood = other.likelihood;
  if (!risk.impact && other.impact) risk.impact = other.impact;
  return risk;
}

function sameSource(a: Source, b: Source): boolean {
  return a.tool === b.tool && a.rawId === b.rawId;
}

function sameEvidence(a: Evidence, b: Evidence): boolean {
  return a.kind === b.kind && a.content === b.content;
}

function absorb(kept: Finding, other: Finding, now: string): Finding {
  const sources = [...kept.sources];
  for (const s of other.sources) if (!sources.some((k) => sameSource(k, s))) sources.push(s);
  const evidence = [...kept.evidence];
  for (const e of other.evidence) if (!evidence.some((k) => sameEvidence(k, e))) evidence.push(e);
  const renumbered = evidence.map((e, i) => ({ ...e, id: `${kept.id}-e${i + 1}`, findingId: kept.id }));
  const phase = isPhaseAfter(other.phase, kept.phase) ? other.phase : kept.phase;
  const merged: Finding = {
    ...kept,
    scope: mergeScope(kept.scope, other.scope),
    impact: kept.impact === UNASSESSED_IMPACT && other.impact !== UNASSESSED_IMPACT ? other.impact : kept.impact,
    fix: kept.fix === UNWRITTEN_FIX && other.fix !== UNWRITTEN_FIX ? other.fix : kept.fix,
    evidence: renumbered,
    risk: mergeRisk(kept.risk, other.risk),
    phase,
    sources,
    mappings: {
      cwe: [...new Set([...kept.mappings.cwe, ...other.mappings.cwe])],
      cve: [...new Set([...kept.mappings.cve, ...other.mappings.cve])],
      owaspTop10: [...new Set([...kept.mappings.owaspTop10, ...other.mappings.owaspTop10])],
      owaspApi: [...new Set([...kept.mappings.owaspApi, ...other.mappings.owaspApi])],
      asvs: [...new Set([...kept.mappings.asvs, ...other.mappings.asvs])],
      cis: [...new Set([...kept.mappings.cis, ...other.mappings.cis])],
    },
    createdAt: kept.createdAt < other.createdAt ? kept.createdAt : other.createdAt,
    updatedAt: now,
  };
  if (!merged.retest && other.retest) merged.retest = other.retest;
  return FindingSchema.parse(merged);
}

/**
 * Fold findings with the same fingerprint into the first one seen. The kept finding keeps its id
 * and title; it gains the other's sources and evidence, the higher severity, the wider scope, a
 * real impact or fix in place of a placeholder, the union of the mappings, and the later phase.
 * Nothing is lost: every source keeps its own rating, and `merged` says what went where.
 */
export function dedupe(findings: Finding[], options: DedupeOptions = {}): Deduped {
  const now = (options.now ?? new Date()).toISOString();
  const kept = new Map<string, Finding>();
  const byId = new Map<string, string>();
  const merges = new Map<string, string[]>();
  for (const f of findings) {
    const key = byId.get(f.id) ?? fingerprint(f);
    const existing = kept.get(key);
    if (!existing) {
      kept.set(key, f);
      byId.set(f.id, key);
      continue;
    }
    kept.set(key, absorb(existing, f, now));
    const from = merges.get(existing.id) ?? [];
    from.push(f.id);
    merges.set(existing.id, from);
  }
  const out = [...kept.values()];
  return { findings: out, merged: out.filter((f) => merges.has(f.id)).map((f) => ({ into: f.id, from: merges.get(f.id)! })) };
}
