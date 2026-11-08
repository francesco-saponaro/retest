import {
  ASVS_V4_CHAPTER_IDS,
  FindingSchema,
  OWASP_API_TOP_10_2023_IDS,
  OWASP_TOP_10_2021_IDS,
  baseScore,
  compareSeverity,
  formatVector,
  lookupCwe,
  parseVector,
  severityFromScore,
  type AsvsChapterId,
  type CisControlNumber,
  type Finding,
  type Mappings,
  type OwaspApiTop10Id,
  type OwaspTop10Id,
  type Risk,
  type Severity,
  type Source,
} from "@retest/schema";

/**
 * Classification: the step between "a tool said so" and "this is what it is".
 *
 * It does two things to each finding. It settles the risk: when a source gives a CVSS vector,
 * the score is computed here, compared with what the tool said, and the finding's severity is set
 * from the computed score; when there is only a severity word, or only a score with no vector,
 * the strongest word is used and a note says the number was taken on trust. And it fills the
 * mappings: every CWE goes through the table in `@retest/schema` and the OWASP, ASVS and CIS
 * columns are the union of what comes back. A cloud check has no CWE of its own, so a small table
 * here says what each Prowler check is about in CWE terms. Nothing is invented: a CWE or a check
 * the tables do not know is reported in `unmapped`, not mapped by guesswork.
 */

export interface CloudCheck {
  /** Matched against the Prowler check id (`iam_root_mfa_enabled`). */
  match: RegExp;
  cwe: number[];
  about: string;
}

/** What the common Prowler checks are, in CWE terms. First match wins. */
export const CLOUD_CHECKS: readonly CloudCheck[] = [
  { match: /mfa/, cwe: [308], about: "a sign-in with no second factor" },
  { match: /^iam_avoid_root_usage$/, cwe: [269], about: "day-to-day use of the most privileged account" },
  { match: /^iam_password_policy_/, cwe: [521], about: "a password policy weaker than the baseline" },
  { match: /^iam_.*(access_?key|accesskey).*(unused|rotat)/, cwe: [324], about: "a credential that is not rotated" },
  { match: /public_access|public_write|public_read|_public$|publicly/, cwe: [284], about: "a resource readable or writable by everyone" },
  { match: /securitygroup_allow_(ingress|wide_open)/, cwe: [1327], about: "a port open to the whole Internet" },
  { match: /^cloudtrail_|logging_enabled|_logging$|flow_logs/, cwe: [778], about: "activity that is not being recorded" },
  { match: /encrypt/, cwe: [311], about: "data at rest or in transit without encryption" },
  { match: /tls|ssl|https_only|secure_transport/, cwe: [319], about: "traffic allowed in clear" },
];

/** The CWEs a Prowler check is about, or undefined when the table has nothing for it. */
export function cloudCheckCwes(checkId: string): number[] | undefined {
  for (const c of CLOUD_CHECKS) if (c.match.test(checkId)) return [...c.cwe];
  return undefined;
}

export interface ClassifyOptions {
  /** The time to stamp on a finding that changed. Defaults to now. */
  now?: Date;
}

export interface Classified {
  findings: Finding[];
  /** What the tables could not place: CWE numbers and Prowler check ids. Ascending, no repeats. */
  unmapped: { cwe: number[]; checks: string[] };
  /** One line per judgement call: a tool's score that disagreed with its vector, a vector that was not v3, a number taken on trust. */
  notes: string[];
}

interface VectorClaim {
  source: Source;
  vector: string;
  score: number;
}

function sortBy<T>(values: Iterable<T>, order: readonly T[]): T[] {
  return [...new Set(values)].sort((a, b) => order.indexOf(a) - order.indexOf(b));
}

function settleRisk(f: Finding, notes: string[]): Risk {
  const claims: VectorClaim[] = [];
  for (const s of f.sources) {
    const vector = s.cvss?.vector;
    if (!vector) continue;
    try {
      const parsed = parseVector(vector);
      const score = baseScore(parsed);
      if (s.cvss?.score !== undefined && s.cvss.score !== score) {
        notes.push(`${f.id}: ${s.tool} says ${s.cvss.score} for ${vector}, which computes to ${score}; ${score} is used`);
      }
      claims.push({ source: s, vector: formatVector(parsed), score });
    } catch {
      notes.push(`${f.id}: ${s.tool}'s vector ${vector} is not CVSS v3; ignored`);
    }
  }
  if (claims.length > 0) {
    const worst = claims.reduce((a, b) => (b.score > a.score ? b : a));
    return { ...f.risk, cvss: { vector: worst.vector, baseScore: worst.score }, severity: severityFromScore(worst.score) };
  }
  if (f.risk.cvss) return f.risk;

  let severity: Severity = f.risk.severity;
  let trusted: { source: Source; score: number } | undefined;
  for (const s of f.sources) {
    if (s.severity && compareSeverity(s.severity, severity) > 0) {
      severity = s.severity;
      trusted = undefined;
    }
    if (s.cvss?.score !== undefined && !s.cvss.vector && s.cvss.score >= 0 && s.cvss.score <= 10) {
      const fromScore = severityFromScore(s.cvss.score);
      if (compareSeverity(fromScore, severity) > 0) {
        severity = fromScore;
        trusted = { source: s, score: s.cvss.score };
      }
    }
  }
  if (trusted) notes.push(`${f.id}: severity ${severity} from ${trusted.source.tool}'s bare score ${trusted.score}, which has no vector to check`);
  return severity === f.risk.severity ? f.risk : { ...f.risk, severity };
}

function settleMappings(f: Finding, unmappedCwe: Set<number>, unmappedChecks: Set<string>): Mappings {
  const cwe = new Set(f.mappings.cwe);
  for (const s of f.sources) {
    if (s.tool !== "prowler") continue;
    const known = cloudCheckCwes(s.rawId);
    if (known) known.forEach((n) => cwe.add(n));
    else unmappedChecks.add(s.rawId);
  }
  const owaspTop10 = new Set<OwaspTop10Id>(f.mappings.owaspTop10);
  const owaspApi = new Set<OwaspApiTop10Id>(f.mappings.owaspApi);
  const asvs = new Set<AsvsChapterId>(f.mappings.asvs);
  const cis = new Set<CisControlNumber>(f.mappings.cis);
  for (const n of cwe) {
    const entry = lookupCwe(n);
    if (!entry) {
      unmappedCwe.add(n);
      continue;
    }
    if (entry.owaspTop10) owaspTop10.add(entry.owaspTop10);
    if (entry.owaspApi) owaspApi.add(entry.owaspApi);
    entry.asvs.forEach((c) => asvs.add(c));
    entry.cis.forEach((c) => cis.add(c));
  }
  return {
    cwe: [...cwe],
    cve: [...new Set(f.mappings.cve)],
    owaspTop10: sortBy(owaspTop10, OWASP_TOP_10_2021_IDS),
    owaspApi: sortBy(owaspApi, OWASP_API_TOP_10_2023_IDS),
    asvs: sortBy(asvs, ASVS_V4_CHAPTER_IDS),
    cis: [...cis].sort((a, b) => a - b),
  };
}

/**
 * Settle the risk and fill the mappings of every finding. A finding that did not change keeps
 * its `updatedAt`; running it twice changes nothing the second time.
 */
export function classify(findings: Finding[], options: ClassifyOptions = {}): Classified {
  const now = (options.now ?? new Date()).toISOString();
  const notes: string[] = [];
  const unmappedCwe = new Set<number>();
  const unmappedChecks = new Set<string>();
  const out = findings.map((f) => {
    const risk = settleRisk(f, notes);
    const mappings = settleMappings(f, unmappedCwe, unmappedChecks);
    const next: Finding = { ...f, risk, mappings };
    const changed = JSON.stringify({ risk: f.risk, mappings: f.mappings }) !== JSON.stringify({ risk, mappings });
    if (changed) next.updatedAt = now;
    return changed ? FindingSchema.parse(next) : f;
  });
  return {
    findings: out,
    unmapped: { cwe: [...unmappedCwe].sort((a, b) => a - b), checks: [...unmappedChecks].sort() },
    notes,
  };
}
