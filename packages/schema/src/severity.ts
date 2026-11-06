import { z } from "zod";

/** The five levels, lowest first. "info" is for things worth recording that carry no risk on their own. */
export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;

export const SeveritySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof SeveritySchema>;

export const SEVERITY_LABELS: Record<Severity, string> = {
  info: "Informational",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

/**
 * The CVSS v3.1 qualitative rating scale (specification, section 5):
 * 0.0 none, 0.1 to 3.9 low, 4.0 to 6.9 medium, 7.0 to 8.9 high, 9.0 to 10.0 critical.
 * "None" is called "info" here, because a finding with no CVSS impact can still be worth a line in the report.
 */
export function severityFromScore(score: number): Severity {
  if (!Number.isFinite(score) || score < 0 || score > 10) {
    throw new RangeError(`CVSS score out of range: ${score}`);
  }
  if (score === 0) return "info";
  if (score < 4) return "low";
  if (score < 7) return "medium";
  if (score < 9) return "high";
  return "critical";
}

/** Positive when a is more severe than b. */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b);
}

/** Most severe first. Does not mutate the input. */
export function sortBySeverity<T extends Severity>(levels: readonly T[]): T[] {
  return [...levels].sort((a, b) => compareSeverity(b, a));
}
