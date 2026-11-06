import { describe, expect, it } from "vitest";
import {
  SEVERITIES,
  SEVERITY_LABELS,
  SeveritySchema,
  compareSeverity,
  severityFromScore,
  sortBySeverity,
} from "../src/severity.js";

describe("severity", () => {
  it("lists the five levels from lowest to highest", () => {
    expect(SEVERITIES).toEqual(["info", "low", "medium", "high", "critical"]);
  });

  it("validates a level and rejects anything else", () => {
    expect(SeveritySchema.parse("high")).toBe("high");
    expect(SeveritySchema.safeParse("urgent").success).toBe(false);
  });

  it("has a label for every level", () => {
    for (const s of SEVERITIES) expect(SEVERITY_LABELS[s]).toBeTypeOf("string");
  });

  it.each([
    [0, "info"],
    [0.1, "low"],
    [3.9, "low"],
    [4.0, "medium"],
    [6.9, "medium"],
    [7.0, "high"],
    [8.9, "high"],
    [9.0, "critical"],
    [10, "critical"],
  ])("maps a CVSS score of %s to %s, as the v3.1 qualitative scale does", (score, severity) => {
    expect(severityFromScore(score)).toBe(severity);
  });

  it("refuses a score outside 0 to 10", () => {
    expect(() => severityFromScore(-1)).toThrow();
    expect(() => severityFromScore(10.1)).toThrow();
  });

  it("compares levels so that critical sorts first in a descending sort", () => {
    expect(compareSeverity("critical", "low")).toBeGreaterThan(0);
    expect(compareSeverity("low", "low")).toBe(0);
    expect(sortBySeverity(["low", "critical", "info", "high"])).toEqual(["critical", "high", "low", "info"]);
  });
});
