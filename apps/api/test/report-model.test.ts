import { describe, expect, it } from "vitest";
import type { Asset, Finding } from "@retest/schema";
import type { AssessmentOut, AuditLine, ImportOut } from "../src/rows.js";
import { buildReport, isVerified, type ReportInput } from "../src/report/model.js";

const at = "2026-11-10T18:00:00.000Z";
const noMappings = { cwe: [], cve: [], owaspTop10: [], owaspApi: [], asvs: [], cis: [] };

const assessment: AssessmentOut = {
  id: "a1",
  ownerId: "francesco",
  name: "Juice Shop lab",
  client: "Me",
  scope: { targets: ["http://127.0.0.1:3000", "bkimminich/juice-shop:v17.1.1"], exclusions: [], authorizedBy: "me", authorizedAt: "2026-11-09T18:00:00Z" },
  phase: "validation",
  status: "active",
  createdAt: at,
  updatedAt: at,
} as AssessmentOut;

const web: Asset = { id: "web", assessmentId: "a1", kind: "web-app", name: "127.0.0.1:3000", url: "http://127.0.0.1:3000", inScope: true, tags: [] };
const image: Asset = { id: "img", assessmentId: "a1", kind: "container-image", name: "bkimminich/juice-shop:v17.1.1", inScope: true, tags: [] };

function finding(p: Partial<Finding> & Pick<Finding, "id" | "title" | "assetId">): Finding {
  return {
    assessmentId: "a1",
    scope: "/",
    impact: "Not assessed yet.",
    fix: "Not written yet.",
    evidence: [],
    risk: { severity: "medium" },
    phase: "assessment",
    status: "open",
    sources: [{ tool: "zap", rawId: "1" }],
    mappings: noMappings,
    createdAt: at,
    updatedAt: at,
    ...p,
  };
}

const jwt = finding({ id: "jwt", title: "jsonwebtoken 0.4.0", assetId: "img", risk: { severity: "critical", cvss: { vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", baseScore: 9.8 } }, phase: "remediation", sources: [{ tool: "trivy", rawId: "x" }], mappings: { ...noMappings, owaspTop10: ["A06"], asvs: ["V14"] } });
const prom = finding({ id: "prom", title: "Prometheus metrics", assetId: "web", risk: { severity: "critical" }, mappings: { ...noMappings, owaspTop10: ["A05"], asvs: ["V14"] } });
const cors = finding({ id: "cors", title: "CORS allows any origin", assetId: "web", risk: { severity: "medium", likelihood: "high", impact: "low" }, phase: "risk", mappings: { ...noMappings, owaspTop10: ["A05", "A01"], asvs: ["V14"] } });
const ts = finding({ id: "ts", title: "Timestamp disclosure", assetId: "web", risk: { severity: "low" }, phase: "validation", status: "false-positive", falsePositiveReason: "Build ids, not times.", mappings: { ...noMappings, owaspTop10: ["A01"] } });
const robots = finding({ id: "robots", title: "robots.txt", assetId: "web", risk: { severity: "info" } });
const fixed = finding({ id: "fixed", title: "Missing CSP", assetId: "web", risk: { severity: "medium" }, phase: "remediation", status: "closed", retest: { outcome: "fixed", testedAt: "2026-11-12T10:00:00.000Z" }, mappings: { ...noMappings, owaspTop10: ["A05"] } });

function imp(tool: ImportOut["tool"], created: number, when: string): ImportOut {
  return { id: `i-${tool}`, assessmentId: "a1", actor: "francesco", tool, filename: null, parsed: created, created, merged: 0, assetsCreated: 0, warnings: [], at: when };
}
function status(fid: string, from: string, to: string, when: string, id: number): AuditLine {
  return { id, assessmentId: "a1", findingId: fid, actor: "francesco", action: "status", field: "status", from, to, reason: null, at: when };
}

const input: ReportInput = {
  assessment,
  assets: [image, web],
  findings: [robots, ts, cors, prom, jwt, fixed],
  imports: [imp("zap", 4, "2026-11-10T09:00:00.000Z"), imp("trivy", 2, "2026-11-11T09:00:00.000Z")],
  audit: [
    status("ts", "open", "false-positive", "2026-11-11T12:00:00.000Z", 1),
    status("fixed", "open", "closed", "2026-11-12T10:00:00.000Z", 2),
    { id: 3, assessmentId: "a1", findingId: null, actor: "francesco", action: "status", field: "status", from: "active", to: "on-hold", reason: null, at: "2026-11-12T11:00:00.000Z" },
  ],
  generatedAt: "2026-11-13T08:00:00.000Z",
};

describe("verified", () => {
  it("means a person took it to validation or later and did not set it aside as false", () => {
    expect(isVerified(jwt)).toBe(true);
    expect(isVerified(cors)).toBe(true);
    expect(isVerified(prom)).toBe(false);
    expect(isVerified(ts)).toBe(false);
  });
});

describe("buildReport", () => {
  const r = buildReport(input);

  it("counts by status, and leaves false positives out of the severity totals", () => {
    expect(r.counts).toMatchObject({ findings: 6, assets: 2, open: 4, closed: 1, falsePositive: 1, acceptedRisk: 0, verified: 3, unverifiedOpen: 2 });
    expect(r.counts.bySeverity).toEqual({ critical: 2, high: 0, medium: 2, low: 0, info: 1 });
  });

  it("groups by asset in name order, most severe first, and marks each finding verified or not", () => {
    expect(r.groups.map((g) => g.asset.id)).toEqual(["web", "img"]);
    expect(r.groups[0]!.findings.map((f) => f.id)).toEqual(["prom", "cors", "fixed", "ts", "robots"]);
    expect(r.groups[1]!.findings[0]).toMatchObject({ id: "jwt", verified: true });
  });

  it("puts verified risks before scanner claims of the same severity, and counts the serious claims nobody has checked", () => {
    expect(r.topRisks.map((f) => f.id)).toEqual(["jwt", "prom", "cors"]);
    expect(r.unverifiedSerious).toBe(1);
  });

  it("draws a day-by-day trend from the imports and the status changes of findings", () => {
    expect(r.trend).toEqual([
      { day: "2026-11-10", found: 4, closed: 0, setAside: 0, reopened: 0, open: 4 },
      { day: "2026-11-11", found: 2, closed: 0, setAside: 1, reopened: 0, open: 5 },
      { day: "2026-11-12", found: 0, closed: 1, setAside: 0, reopened: 0, open: 4 },
    ]);
  });

  it("builds an OWASP Top 10 matrix that tells 'nothing found' apart from 'nothing looked'", () => {
    const row = (id: string) => r.coverage.owasp.find((x) => x.id === id)!;
    expect(r.coverage.toolsRun).toEqual(["zap", "trivy"]);
    expect(row("A05")).toMatchObject({ findings: 3, open: 2, verified: 2, lookedBy: ["zap"], state: "found" });
    expect(row("A01")).toMatchObject({ findings: 1, state: "found" });
    expect(row("A06")).toMatchObject({ findings: 1, lookedBy: ["zap", "trivy"], state: "found" });
    expect(row("A02")).toMatchObject({ findings: 0, lookedBy: ["zap"], state: "clean" });
    expect(row("A03")).toMatchObject({ findings: 0, lookedBy: [], state: "not-tested" });
    expect(row("A04")).toMatchObject({ state: "not-tested" });
    expect(r.coverage.owasp).toHaveLength(10);
  });

  it("builds the ASVS rows from the findings only, since no tool proves a chapter passes", () => {
    expect(r.coverage.asvs).toHaveLength(14);
    expect(r.coverage.asvs.find((x) => x.id === "V14")).toMatchObject({ findings: 3, state: "found" });
    expect(r.coverage.asvs.find((x) => x.id === "V2")).toMatchObject({ findings: 0, lookedBy: [], state: "not-tested" });
  });

  it("is the same report for the same input", () => {
    expect(buildReport(input)).toEqual(r);
  });
});
