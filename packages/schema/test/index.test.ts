import { describe, expect, it } from "vitest";
import * as schema from "../src/index.js";

describe("package entry point", () => {
  it("exports the schemas, the constants and the CVSS helpers", () => {
    const names = [
      "FindingSchema",
      "AssetSchema",
      "EvidenceSchema",
      "AssessmentSchema",
      "SourceSchema",
      "RiskSchema",
      "RetestSchema",
      "PhaseSchema",
      "SeveritySchema",
      "CvssSchema",
      "PHASES",
      "SEVERITIES",
      "TOOLS",
      "FINDING_FIELDS",
      "OWASP_TOP_10_2021",
      "OWASP_API_TOP_10_2023",
      "ASVS_V4_CHAPTERS",
      "CIS_CONTROLS_V8",
      "parseVector",
      "baseScore",
      "scoreVector",
      "severityFromScore",
      "lookupCwe",
    ];
    for (const n of names) expect(schema, n).toHaveProperty(n);
  });
});
