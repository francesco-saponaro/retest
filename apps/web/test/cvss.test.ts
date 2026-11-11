import { formatVector, parseVector, scoreVector } from "@retest/schema";
import { describe, expect, it } from "vitest";
import { BASE_METRICS, DEFAULT_VECTOR, claimsAgainst, riskFromVector, startingVector, withMetric } from "../src/lib/cvss.js";
import { cors, jwt, login } from "./findings.js";

describe("startingVector", () => {
  it("starts from the finding's own vector, else a source's, else the harmless default", () => {
    expect(startingVector(jwt)).toBe("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    const claimed = { ...login, sources: [{ ...login.sources[0]!, cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" } }] };
    expect(startingVector(claimed)).toBe("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
    expect(startingVector(cors)).toBe(DEFAULT_VECTOR);
    expect(scoreVector(DEFAULT_VECTOR).baseScore).toBe(0);
  });
});

describe("BASE_METRICS and withMetric", () => {
  it("lists the eight base metrics in the specification's order with every value named", () => {
    expect(BASE_METRICS.map((m) => m.key)).toEqual(["AV", "AC", "PR", "UI", "S", "C", "I", "A"]);
    expect(BASE_METRICS[0]!.values.map((v) => v.code)).toEqual(["N", "A", "L", "P"]);
    expect(BASE_METRICS[0]!.values[0]!.label).toBe("Network");
  });

  it("changes one metric and keeps the rest, as a canonical string", () => {
    const v = withMetric(parseVector(DEFAULT_VECTOR), "C", "H");
    expect(formatVector(v)).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
    expect(scoreVector(v).baseScore).toBe(7.5);
  });
});

describe("riskFromVector", () => {
  it("builds the finding's risk the schema accepts: the severity is the score's", () => {
    expect(riskFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toEqual({ severity: "critical", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", baseScore: 9.8 } });
    expect(riskFromVector(DEFAULT_VECTOR)).toEqual({ severity: "info", cvss: { vector: DEFAULT_VECTOR, baseScore: 0 } });
  });
});

describe("claimsAgainst", () => {
  it("compares what each tool claimed with the vector on screen", () => {
    expect(claimsAgainst(jwt, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toEqual([{ tool: "trivy", claim: "9.8, the same vector", agrees: true }]);
    expect(claimsAgainst(jwt, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")).toEqual([{ tool: "trivy", claim: "9.8 from CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", agrees: false }]);
    expect(claimsAgainst(cors, DEFAULT_VECTOR)).toEqual([
      { tool: "nuclei", claim: "low, no vector", agrees: null },
      { tool: "zap", claim: "medium, no vector", agrees: null },
    ]);
  });
});
