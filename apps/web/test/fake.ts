import { phaseChangeProblem, retestProblem, statusChangeProblem, type Asset, type Evidence, type Finding, type Phase } from "@retest/schema";
import type { AuditLine, FindingSummary, ImportOut } from "@retest/api/rows.js";
import type { Totals } from "@retest/api/services/assessments.js";
import { ApiError, type ApiClient, type AssessmentDetail, type AssessmentSummary, type FindingFilter } from "../src/api/client.js";
import { buildReport } from "@retest/api/report/model.js";
import { summaryMarkdown, technicalMarkdown } from "@retest/api/report/markdown.js";
import { detailOf, juiceFindings, summaryOf } from "./findings.js";

/** Totals with every bucket at zero unless given; the finding count is the sum of the phases. */
export function totalsOf(byPhase: Partial<Record<Phase, number>>, extra: Partial<Totals> = {}): Totals {
  const phases: Totals["byPhase"] = { scope: 0, recon: 0, assessment: 0, validation: 0, risk: 0, remediation: 0, ...byPhase };
  const findings = Object.values(phases).reduce((a, b) => a + b, 0);
  return {
    findings,
    assets: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byPhase: phases,
    byStatus: { open: findings, "false-positive": 0, "accepted-risk": 0, closed: 0 },
    ...extra,
  };
}

const at = "2026-11-10T18:00:00.000Z";

export const juice: AssessmentSummary = {
  id: "a-juice",
  ownerId: "francesco",
  name: "Juice Shop lab",
  client: "Retest lab",
  scope: { targets: ["127.0.0.1", "http://127.0.0.1:3000", "juice-shop", "bkimminich/juice-shop:v17.1.1", "123456789012"], exclusions: [], authorizedBy: "francesco", authorizedAt: at },
  phase: "assessment",
  status: "active",
  createdAt: at,
  updatedAt: at,
};

export const network: AssessmentSummary = {
  id: "a-network",
  ownerId: "francesco",
  name: "Lab network",
  scope: { targets: ["10.0.10.0/24"], exclusions: [], authorizedBy: "francesco", authorizedAt: at },
  phase: "recon",
  status: "active",
  createdAt: "2026-11-09T18:00:00.000Z",
  updatedAt: "2026-11-09T18:00:00.000Z",
};

export const juiceDetail: AssessmentDetail = {
  ...juice,
  totals: totalsOf(
    { recon: 4, assessment: 33 },
    { assets: 5, bySeverity: { critical: 4, high: 7, medium: 11, low: 3, info: 12 }, byStatus: { open: 37, "false-positive": 0, "accepted-risk": 0, closed: 0 } },
  ),
};

/** The same assessment with totals that agree with the six fake findings, for the table's tests. */
export const juiceSix: AssessmentDetail = {
  ...juice,
  totals: totalsOf({ recon: 1, assessment: 4, remediation: 1 }, { assets: 5, bySeverity: { critical: 2, high: 1, medium: 2, low: 0, info: 1 }, byStatus: { open: 6, "false-positive": 0, "accepted-risk": 0, closed: 0 } }),
};

export const juiceAssets: Asset[] = [
  { id: "asset-host-127-0-0-1", assessmentId: "a-juice", kind: "host", name: "127.0.0.1", host: "127.0.0.1", inScope: true, tags: [] },
  { id: "asset-web-127-0-0-1-3000", assessmentId: "a-juice", kind: "web-app", name: "http://127.0.0.1:3000", url: "http://127.0.0.1:3000", inScope: true, tags: [] },
  { id: "asset-repo-juice-shop", assessmentId: "a-juice", kind: "repository", name: "juice-shop", inScope: true, tags: [] },
  { id: "asset-image-juice-shop", assessmentId: "a-juice", kind: "container-image", name: "bkimminich/juice-shop:v17.1.1", inScope: true, tags: [] },
  { id: "asset-cloud-123456789012", assessmentId: "a-juice", kind: "cloud-account", name: "123456789012", inScope: false, tags: [] },
];

export const juiceImports: ImportOut[] = [
  { id: "imp-1", assessmentId: "a-juice", actor: "francesco", tool: "nmap", filename: "nmap/juice-shop.xml", parsed: 4, created: 4, merged: 0, assetsCreated: 2, warnings: [], at },
  { id: "imp-2", assessmentId: "a-juice", actor: "francesco", tool: "nuclei", filename: "nuclei/juice-shop.jsonl", parsed: 11, created: 11, merged: 0, assetsCreated: 0, warnings: [], at },
  { id: "imp-3", assessmentId: "a-juice", actor: "francesco", tool: "zap", filename: "zap/juice-shop.json", parsed: 6, created: 3, merged: 3, assetsCreated: 0, warnings: [], at },
  { id: "imp-6", assessmentId: "a-juice", actor: "francesco", tool: "prowler", filename: "prowler/lab-account.ocsf.json", parsed: 7, created: 7, merged: 0, assetsCreated: 1, warnings: ["finding 7 is MANUAL: not imported"], at },
];

export const juiceAudit: AuditLine[] = [
  { id: 1, assessmentId: "a-juice", findingId: null, actor: "francesco", action: "status", field: "status", from: "draft", to: "active", reason: "The lab is mine to scan.", at },
  { id: 2, assessmentId: "a-juice", findingId: null, actor: "francesco", action: "phase", field: "phase", from: "scope", to: "assessment", reason: "Scope and recon done by the lab script.", at },
  { id: 3, assessmentId: "a-juice", findingId: null, actor: "francesco", action: "import", field: "nmap", from: "nmap/juice-shop.xml", to: "4 parsed, 4 created, 0 merged", reason: null, at },
  { id: 4, assessmentId: "a-juice", findingId: "f-csp", actor: "francesco", action: "phase", field: "phase", from: "assessment", to: "validation", reason: "No CSP header on any of the three paths.", at: "2026-11-12T18:00:00.000Z" },
  { id: 5, assessmentId: "a-juice", findingId: "f-csp", actor: "francesco", action: "phase", field: "phase", from: "validation", to: "risk", reason: null, at: "2026-11-12T18:10:00.000Z" },
  { id: 6, assessmentId: "a-juice", findingId: "f-csp", actor: "francesco", action: "phase", field: "phase", from: "risk", to: "remediation", reason: null, at: "2026-11-12T18:20:00.000Z" },
  { id: 7, assessmentId: "a-juice", findingId: "f-csp", actor: "francesco", action: "retest", field: "retest", from: null, to: "not-fixed", reason: "No Content-Security-Policy header on GET / after the deploy.", at: "2026-11-13T18:00:00.000Z" },
];

/** The findings the fake client lists, filtered in memory the way the API filters them. */
export function filterFindings(items: FindingSummary[], f: FindingFilter): FindingSummary[] {
  const q = f.q?.toLowerCase();
  return items.filter(
    (x) =>
      (!f.severity || x.risk.severity === f.severity) &&
      (!f.phase || x.phase === f.phase) &&
      (!f.tool || x.sources.some((s) => s.tool === f.tool)) &&
      (!f.owasp || x.mappings.owaspTop10.includes(f.owasp)) &&
      (!f.assetId || x.assetId === f.assetId) &&
      (!q || x.title.toLowerCase().includes(q) || x.scope.toLowerCase().includes(q)),
  );
}

/**
 * A client that answers from the objects above, as the API would. The workflow calls apply the
 * schema's own rules and refuse with the same sentences and the same 409.
 */
export function fakeClient(overrides: Partial<ApiClient> = {}): ApiClient {
  const notFound = (what = "assessment") => Promise.reject(new ApiError(404, `${what} not found`));
  const findings = new Map(juiceFindings.map((f) => [f.id, structuredClone(f)]));
  const audit: AuditLine[] = structuredClone(juiceAudit);
  const stamp = "2026-11-14T20:00:00.000Z";
  const must = (fid: string): Finding => {
    const f = findings.get(fid);
    if (!f) throw new ApiError(404, "finding not found");
    return f;
  };
  const line = (f: Finding, action: AuditLine["action"], from: string | null, to: string | null, reason?: string) => {
    audit.push({ id: audit.length + 1, assessmentId: f.assessmentId, findingId: f.id, actor: "francesco", action, field: action, from, to, reason: reason ?? null, at: stamp });
  };
  const report = () => buildReport({ assessment: juice, assets: juiceAssets, findings: [...findings.values()], imports: juiceImports, audit, generatedAt: stamp });
  const refuse = (problem: string | null) => {
    if (problem) throw new ApiError(409, problem);
  };
  return {
    mode: "api",
    listAssessments: async () => [juice, network],
    getAssessment: async (id) => (id === "a-juice" ? juiceDetail : notFound()),
    listAssets: async (id) => (id === "a-juice" ? juiceAssets : notFound()),
    listImports: async (id) => (id === "a-juice" ? juiceImports : notFound()),
    listAudit: async (id) => (id === "a-juice" ? audit : notFound()),
    listFindings: async (id, filter) => {
      if (id !== "a-juice") return notFound();
      const items = filterFindings([...findings.values()].map(summaryOf), filter);
      return { items, total: items.length, limit: 500, offset: 0 };
    },
    getFinding: async (fid) => {
      const f = findings.get(fid);
      return f ? detailOf(f) : notFound("finding");
    },
    updateFinding: async (fid, patch) => {
      const f = must(fid);
      refuse(f.status === "closed" ? "the finding is closed: the retest found it fixed; reopen it first" : null);
      const updated: Finding = { ...f, ...(patch.risk ? { risk: patch.risk } : {}), ...(patch.impact !== undefined ? { impact: patch.impact } : {}), ...(patch.fix !== undefined ? { fix: patch.fix } : {}), updatedAt: stamp };
      findings.set(fid, updated);
      return updated;
    },
    setFindingPhase: async (fid, { phase, reason }) => {
      const f = must(fid);
      refuse(phaseChangeProblem(f, phase, reason));
      if (f.phase !== phase) {
        line(f, "phase", f.phase, phase, reason);
        findings.set(fid, { ...f, phase, updatedAt: stamp });
      }
      return must(fid);
    },
    setFindingStatus: async (fid, { status, reason }) => {
      const f = must(fid);
      refuse(statusChangeProblem(f, status, reason));
      const phase: Phase = status === "false-positive" && (f.phase === "scope" || f.phase === "recon" || f.phase === "assessment") ? "validation" : f.phase;
      if (phase !== f.phase) line(f, "phase", f.phase, phase, "Found to be a false positive.");
      line(f, "status", f.status, status, reason);
      const next: Finding = { ...f, status, phase, updatedAt: stamp };
      if (status === "false-positive") next.falsePositiveReason = reason!;
      else delete next.falsePositiveReason;
      findings.set(fid, next);
      return next;
    },
    recordRetest: async (fid, input) => {
      const f = must(fid);
      refuse(retestProblem(f, input.outcome));
      const retest = { outcome: input.outcome, testedAt: input.testedAt ?? stamp, notes: input.notes };
      line(f, "retest", f.retest?.outcome ?? null, input.outcome, input.notes);
      const status = input.outcome === "fixed" ? "closed" : f.status;
      if (status !== f.status) line(f, "status", f.status, status, "The retest found it fixed.");
      const next: Finding = { ...f, retest, status, updatedAt: stamp };
      findings.set(fid, next);
      return next;
    },
    addEvidence: async (fid, input) => {
      const f = must(fid);
      const piece: Evidence = { id: `ev-new-${f.evidence.length + 1}`, findingId: fid, kind: input.kind, content: input.content, redacted: input.redacted ?? false, ...(input.title ? { title: input.title } : {}) };
      findings.set(fid, { ...f, evidence: [...f.evidence, piece], updatedAt: stamp });
      return piece;
    },
    updateEvidence: async (eid, patch) => {
      for (const f of findings.values()) {
        const i = f.evidence.findIndex((e) => e.id === eid);
        if (i < 0) continue;
        const piece: Evidence = { ...f.evidence[i]!, ...(patch.content !== undefined ? { content: patch.content } : {}), ...(patch.redacted !== undefined ? { redacted: patch.redacted } : {}), ...(patch.title !== undefined ? { title: patch.title } : {}) };
        findings.set(f.id, { ...f, evidence: f.evidence.map((e, j) => (j === i ? piece : e)) });
        return piece;
      }
      throw new ApiError(404, "evidence not found");
    },
    listFindingAudit: async (fid) => {
      must(fid);
      return audit.filter((l) => l.findingId === fid);
    },
    getReport: async (id) => (id === "a-juice" ? report() : notFound()),
    getReportMarkdown: async (id, kind) => (id === "a-juice" ? (kind === "summary" ? summaryMarkdown(report()) : technicalMarkdown(report())) : notFound()),
    ...overrides,
  };
}
