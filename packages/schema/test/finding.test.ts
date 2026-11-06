import { describe, expect, it } from "vitest";
import {
  FINDING_FIELDS,
  FINDING_STATUSES,
  FindingSchema,
  RETEST_OUTCOMES,
  RetestSchema,
  RiskSchema,
  newFinding,
} from "../src/finding.js";

const minimal = {
  id: "f-1",
  assessmentId: "assessment-lab",
  title: "SQL injection in the product search",
  assetId: "asset-juice-shop",
  scope: "GET /rest/products/search?q=",
  impact: "Anyone on the network can read every row of the products and users tables.",
  risk: { severity: "high" },
  fix: "Use a parameterised query in the search handler.",
  createdAt: "2026-11-06T18:00:00Z",
  updatedAt: "2026-11-06T18:00:00Z",
};

describe("the seven fields", () => {
  it("are the ones the roadmap asks for, in its order", () => {
    expect(FINDING_FIELDS.map((f) => f.key)).toEqual(["title", "asset", "impact", "evidence", "risk", "fix", "retest"]);
    for (const f of FINDING_FIELDS) {
      expect(f.label.length).toBeGreaterThan(0);
      expect(f.question.length).toBeGreaterThan(0);
    }
  });
});

describe("Risk", () => {
  it("needs at least a severity", () => {
    expect(RiskSchema.parse({ severity: "medium" })).toEqual({ severity: "medium" });
    expect(RiskSchema.safeParse({}).success).toBe(false);
  });

  it("carries likelihood, impact and a CVSS score when there is one", () => {
    const r = RiskSchema.parse({
      severity: "high",
      likelihood: "high",
      impact: "medium",
      cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", baseScore: 7.5 },
    });
    expect(r.cvss?.baseScore).toBe(7.5);
  });

  it("rejects a severity that contradicts the CVSS score", () => {
    const r = RiskSchema.safeParse({
      severity: "low",
      cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", baseScore: 7.5 },
    });
    expect(r.success).toBe(false);
  });
});

describe("Retest", () => {
  it("records an outcome and when it was tested", () => {
    expect(RETEST_OUTCOMES).toEqual(["pending", "fixed", "partially-fixed", "not-fixed"]);
    const r = RetestSchema.parse({ outcome: "fixed", testedAt: "2026-11-20T10:00:00Z", notes: "Query is parameterised now." });
    expect(r.outcome).toBe("fixed");
  });

  it("needs a date once the outcome is no longer pending", () => {
    expect(RetestSchema.safeParse({ outcome: "pending" }).success).toBe(true);
    expect(RetestSchema.safeParse({ outcome: "fixed" }).success).toBe(false);
  });
});

describe("Finding", () => {
  it("parses a minimal finding and fills the defaults", () => {
    const f = FindingSchema.parse(minimal);
    expect(f.phase).toBe("assessment");
    expect(f.status).toBe("open");
    expect(f.evidence).toEqual([]);
    expect(f.sources).toEqual([]);
    expect(f.mappings).toEqual({ cwe: [], owaspTop10: [], owaspApi: [], asvs: [], cis: [] });
    expect(f.retest).toBeUndefined();
  });

  it("lists the statuses", () => {
    expect(FINDING_STATUSES).toEqual(["open", "false-positive", "accepted-risk", "closed"]);
  });

  it.each(["title", "assetId", "scope", "impact", "risk", "fix"])("requires %s", (field) => {
    const copy: Record<string, unknown> = { ...minimal };
    delete copy[field];
    expect(FindingSchema.safeParse(copy).success).toBe(false);
  });

  it("rejects an empty title and a title over 200 characters", () => {
    expect(FindingSchema.safeParse({ ...minimal, title: "" }).success).toBe(false);
    expect(FindingSchema.safeParse({ ...minimal, title: "x".repeat(201) }).success).toBe(false);
  });

  it("validates the embedded evidence, sources and mappings", () => {
    const f = FindingSchema.parse({
      ...minimal,
      evidence: [{ id: "ev-1", kind: "request-response", content: "GET /rest/products/search?q=')) HTTP/1.1" }],
      sources: [
        { tool: "zap", rawId: "40018" },
        { tool: "manual", rawId: "burp-repeater-3" },
      ],
      mappings: { cwe: [89], owaspTop10: ["A03"], asvs: ["V5"], cis: [16] },
    });
    expect(f.evidence[0]?.redacted).toBe(false);
    expect(f.sources).toHaveLength(2);
    expect(f.mappings.owaspApi).toEqual([]);
    expect(FindingSchema.safeParse({ ...minimal, mappings: { owaspTop10: ["A11"] } }).success).toBe(false);
    expect(FindingSchema.safeParse({ ...minimal, mappings: { cis: [19] } }).success).toBe(false);
  });

  it("needs a reason to be a false positive", () => {
    expect(FindingSchema.safeParse({ ...minimal, status: "false-positive" }).success).toBe(false);
    expect(
      FindingSchema.safeParse({ ...minimal, status: "false-positive", falsePositiveReason: "The parameter is never used in a query." })
        .success,
    ).toBe(true);
  });

  it("cannot be closed without a retest outcome of fixed", () => {
    expect(FindingSchema.safeParse({ ...minimal, status: "closed" }).success).toBe(false);
    expect(FindingSchema.safeParse({ ...minimal, status: "closed", retest: { outcome: "not-fixed", testedAt: "2026-11-20T10:00:00Z" } }).success).toBe(false);
    expect(FindingSchema.safeParse({ ...minimal, status: "closed", retest: { outcome: "fixed", testedAt: "2026-11-20T10:00:00Z" } }).success).toBe(true);
  });

  it("checks the dates", () => {
    expect(FindingSchema.safeParse({ ...minimal, createdAt: "6 Nov" }).success).toBe(false);
  });
});

describe("newFinding", () => {
  it("builds a finding with fresh timestamps and the defaults filled", () => {
    const f = newFinding({
      id: "f-2",
      assessmentId: "assessment-lab",
      title: "Server banner reveals the Express version",
      assetId: "asset-juice-shop",
      scope: "HTTP response headers",
      impact: "An attacker learns the framework version and can look up known bugs for it.",
      risk: { severity: "low" },
      fix: "Disable the X-Powered-By header.",
    });
    expect(f.phase).toBe("assessment");
    expect(f.createdAt).toBe(f.updatedAt);
    expect(() => new Date(f.createdAt).toISOString()).not.toThrow();
    expect(FindingSchema.safeParse(f).success).toBe(true);
  });
});
