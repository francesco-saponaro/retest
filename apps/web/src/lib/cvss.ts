import { baseScore, formatVector, isValidVector, parseVector, severityFromScore, type CvssVector, type Finding, type Risk } from "@retest/schema";

/**
 * The calculator's side of CVSS v3.1: the eight base metrics with their values named as the
 * specification names them, and the small steps between a finding, a vector and the finding's risk.
 * The scoring itself is the schema package's; nothing here computes a number.
 */
export type BaseMetricKey = "AV" | "AC" | "PR" | "UI" | "S" | "C" | "I" | "A";

export interface MetricValue {
  code: string;
  label: string;
}

export interface Metric {
  key: BaseMetricKey;
  label: string;
  values: readonly MetricValue[];
}

const IMPACT_VALUES: readonly MetricValue[] = [
  { code: "N", label: "None" },
  { code: "L", label: "Low" },
  { code: "H", label: "High" },
];

export const BASE_METRICS: readonly Metric[] = [
  {
    key: "AV",
    label: "Attack vector",
    values: [
      { code: "N", label: "Network" },
      { code: "A", label: "Adjacent" },
      { code: "L", label: "Local" },
      { code: "P", label: "Physical" },
    ],
  },
  {
    key: "AC",
    label: "Attack complexity",
    values: [
      { code: "L", label: "Low" },
      { code: "H", label: "High" },
    ],
  },
  {
    key: "PR",
    label: "Privileges required",
    values: [
      { code: "N", label: "None" },
      { code: "L", label: "Low" },
      { code: "H", label: "High" },
    ],
  },
  {
    key: "UI",
    label: "User interaction",
    values: [
      { code: "N", label: "None" },
      { code: "R", label: "Required" },
    ],
  },
  {
    key: "S",
    label: "Scope",
    values: [
      { code: "U", label: "Unchanged" },
      { code: "C", label: "Changed" },
    ],
  },
  { key: "C", label: "Confidentiality", values: IMPACT_VALUES },
  { key: "I", label: "Integrity", values: IMPACT_VALUES },
  { key: "A", label: "Availability", values: IMPACT_VALUES },
];

/** Every metric at its least severe value: the score is 0.0 and nothing is claimed. */
export const DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";

/** Where the calculator opens: the finding's own vector, else the first tool's vector that parses, else the default. */
export function startingVector(f: Pick<Finding, "risk" | "sources">): string {
  if (f.risk.cvss) return f.risk.cvss.vector;
  for (const s of f.sources) {
    const v = s.cvss?.vector;
    if (v && isValidVector(v)) return formatVector(parseVector(v));
  }
  return DEFAULT_VECTOR;
}

/** The vector with one metric changed. The version and the other metrics stay. */
export function withMetric(vector: CvssVector, key: BaseMetricKey, code: string): CvssVector {
  return { ...vector, [key]: code } as CvssVector;
}

/** The risk the schema accepts for a vector: its base score, and the severity that score gives. */
export function riskFromVector(vector: string): Risk {
  const canonical = formatVector(parseVector(vector));
  const score = baseScore(canonical);
  return { severity: severityFromScore(score), cvss: { vector: canonical, baseScore: score } };
}

export interface Claim {
  tool: string;
  /** "9.8, the same vector", "9.8 from CVSS:3.0/…", "medium, no vector". */
  claim: string;
  /** True when the tool's vector is the one on screen, false when it differs, null when the tool gave none. */
  agrees: boolean | null;
}

/** What each tool said the risk was, set against the vector on screen. */
export function claimsAgainst(f: Pick<Finding, "sources">, vector: string): Claim[] {
  const current = isValidVector(vector) ? formatVector(parseVector(vector)) : null;
  return f.sources.map((s) => {
    const v = s.cvss?.vector;
    const theirs = v && isValidVector(v) ? formatVector(parseVector(v)) : null;
    const score = s.cvss?.score !== undefined ? s.cvss.score.toFixed(1) : theirs ? baseScore(theirs).toFixed(1) : null;
    if (theirs) {
      const same = theirs === current;
      return { tool: s.tool, claim: same ? `${score}, the same vector` : `${score} from ${theirs}`, agrees: same };
    }
    const word = s.severity ?? (score ? `score ${score}` : "no rating");
    return { tool: s.tool, claim: `${word}, no vector`, agrees: null };
  });
}
