import { z } from "zod";
import { severityFromScore, type Severity } from "./severity.js";

/**
 * CVSS v3.1 base and temporal scoring, as in the specification at
 * https://www.first.org/cvss/v3.1/specification-document (sections 6 and 7).
 * Environmental metrics (CR, IR, AR, MAV and the rest) are not supported: a vector that carries them is rejected.
 */

export const CVSS_VERSIONS = ["3.0", "3.1"] as const;
export type CvssVersion = (typeof CVSS_VERSIONS)[number];

const BASE_METRICS = {
  AV: ["N", "A", "L", "P"],
  AC: ["L", "H"],
  PR: ["N", "L", "H"],
  UI: ["N", "R"],
  S: ["U", "C"],
  C: ["H", "L", "N"],
  I: ["H", "L", "N"],
  A: ["H", "L", "N"],
} as const;

const TEMPORAL_METRICS = {
  E: ["X", "U", "P", "F", "H"],
  RL: ["X", "O", "T", "W", "U"],
  RC: ["X", "U", "R", "C"],
} as const;

type BaseMetric = keyof typeof BASE_METRICS;
type TemporalMetric = keyof typeof TEMPORAL_METRICS;

const BASE_ORDER: readonly BaseMetric[] = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
const TEMPORAL_ORDER: readonly TemporalMetric[] = ["E", "RL", "RC"];

export interface CvssVector {
  version: CvssVersion;
  AV: (typeof BASE_METRICS.AV)[number];
  AC: (typeof BASE_METRICS.AC)[number];
  PR: (typeof BASE_METRICS.PR)[number];
  UI: (typeof BASE_METRICS.UI)[number];
  S: (typeof BASE_METRICS.S)[number];
  C: (typeof BASE_METRICS.C)[number];
  I: (typeof BASE_METRICS.I)[number];
  A: (typeof BASE_METRICS.A)[number];
  E?: (typeof TEMPORAL_METRICS.E)[number];
  RL?: (typeof TEMPORAL_METRICS.RL)[number];
  RC?: (typeof TEMPORAL_METRICS.RC)[number];
}

export class CvssError extends Error {
  override name = "CvssError";
}

function isBaseMetric(key: string): key is BaseMetric {
  return key in BASE_METRICS;
}

function isTemporalMetric(key: string): key is TemporalMetric {
  return key in TEMPORAL_METRICS;
}

/** Parse a vector string such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`. Metrics may come in any order. */
export function parseVector(input: string): CvssVector {
  const parts = input.trim().split("/");
  const head = parts.shift();
  const version = head?.startsWith("CVSS:") ? head.slice(5) : undefined;
  if (version !== "3.0" && version !== "3.1") {
    throw new CvssError(`expected a CVSS:3.0 or CVSS:3.1 prefix in "${input}"`);
  }

  const seen = new Map<string, string>();
  for (const part of parts) {
    const [key, value, ...rest] = part.split(":");
    if (!key || value === undefined || rest.length > 0) {
      throw new CvssError(`malformed metric "${part}" in "${input}"`);
    }
    if (seen.has(key)) throw new CvssError(`metric ${key} appears twice in "${input}"`);
    const allowed: readonly string[] | undefined = isBaseMetric(key)
      ? BASE_METRICS[key]
      : isTemporalMetric(key)
        ? TEMPORAL_METRICS[key]
        : undefined;
    if (!allowed) throw new CvssError(`unknown metric ${key} in "${input}"`);
    if (!allowed.includes(value)) throw new CvssError(`metric ${key} cannot be "${value}" in "${input}"`);
    seen.set(key, value);
  }

  for (const metric of BASE_ORDER) {
    if (!seen.has(metric)) throw new CvssError(`metric ${metric} is missing from "${input}"`);
  }

  const vector = { version } as CvssVector;
  for (const [key, value] of seen) {
    (vector as unknown as Record<string, string>)[key] = value;
  }
  return vector;
}

/** The canonical string for a vector: base metrics in the specification's order, then any temporal ones. */
export function formatVector(vector: CvssVector): string {
  const parts = [`CVSS:${vector.version}`];
  for (const m of BASE_ORDER) parts.push(`${m}:${vector[m]}`);
  for (const m of TEMPORAL_ORDER) {
    const v = vector[m];
    if (v !== undefined) parts.push(`${m}:${v}`);
  }
  return parts.join("/");
}

const WEIGHT = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  PR: {
    unchanged: { N: 0.85, L: 0.62, H: 0.27 },
    changed: { N: 0.85, L: 0.68, H: 0.5 },
  },
  E: { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 },
  RL: { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 },
  RC: { X: 1, U: 0.92, R: 0.96, C: 1 },
} as const;

/**
 * Roundup as defined in v3.1 appendix A: round up to one decimal, but ignore floating-point noise
 * below the fifth decimal, so that 4.000000001 is 4.0 and not 4.1.
 */
export function roundUp(value: number): number {
  const int = Math.round(value * 100000);
  if (int % 10000 === 0) return int / 100000;
  return (Math.floor(int / 10000) + 1) / 10;
}

function toVector(v: CvssVector | string): CvssVector {
  return typeof v === "string" ? parseVector(v) : v;
}

/** ISS (impact sub score base) and the Impact sub score, adjusted when the scope changes. */
export function impactSubScore(v: CvssVector | string): number {
  const vec = toVector(v);
  const iss = 1 - (1 - WEIGHT.CIA[vec.C]) * (1 - WEIGHT.CIA[vec.I]) * (1 - WEIGHT.CIA[vec.A]);
  if (vec.S === "U") return 6.42 * iss;
  return 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
}

export function exploitabilitySubScore(v: CvssVector | string): number {
  const vec = toVector(v);
  const pr = vec.S === "C" ? WEIGHT.PR.changed[vec.PR] : WEIGHT.PR.unchanged[vec.PR];
  return 8.22 * WEIGHT.AV[vec.AV] * WEIGHT.AC[vec.AC] * pr * WEIGHT.UI[vec.UI];
}

/** The base score, 0.0 to 10.0. */
export function baseScore(v: CvssVector | string): number {
  const vec = toVector(v);
  const impact = impactSubScore(vec);
  if (impact <= 0) return 0;
  const exploitability = exploitabilitySubScore(vec);
  if (vec.S === "U") return roundUp(Math.min(impact + exploitability, 10));
  return roundUp(Math.min(1.08 * (impact + exploitability), 10));
}

/** The temporal score. Equals the base score when no temporal metric is set (or all are X). */
export function temporalScore(v: CvssVector | string): number {
  const vec = toVector(v);
  const base = baseScore(vec);
  return roundUp(base * WEIGHT.E[vec.E ?? "X"] * WEIGHT.RL[vec.RL ?? "X"] * WEIGHT.RC[vec.RC ?? "X"]);
}

export interface CvssScores {
  /** The vector written in canonical order. */
  vector: string;
  baseScore: number;
  temporalScore: number;
  impactSubScore: number;
  exploitabilitySubScore: number;
  severity: Severity;
}

/** Everything the UI shows for one vector. */
export function scoreVector(v: CvssVector | string): CvssScores {
  const vec = toVector(v);
  const base = baseScore(vec);
  return {
    vector: formatVector(vec),
    baseScore: base,
    temporalScore: temporalScore(vec),
    impactSubScore: impactSubScore(vec),
    exploitabilitySubScore: exploitabilitySubScore(vec),
    severity: severityFromScore(base),
  };
}

export function isValidVector(input: string): boolean {
  try {
    parseVector(input);
    return true;
  } catch {
    return false;
  }
}

export const CvssVectorStringSchema = z.string().refine(isValidVector, { message: "not a valid CVSS v3.x vector" });

/** A vector with its base score. The score must be the one the vector computes to, so nobody can store a made-up number. */
export const CvssSchema = z
  .object({
    vector: CvssVectorStringSchema,
    baseScore: z.number().min(0).max(10),
  })
  .refine((c) => !isValidVector(c.vector) || baseScore(c.vector) === c.baseScore, {
    message: "baseScore does not match the vector",
    path: ["baseScore"],
  });

export type Cvss = z.infer<typeof CvssSchema>;
