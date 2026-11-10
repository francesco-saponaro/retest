import type { Asset, Phase } from "@retest/schema";
import type { AuditLine, ImportOut } from "@retest/api/rows.js";
import type { Totals } from "@retest/api/services/assessments.js";
import { ApiError, type ApiClient, type AssessmentDetail, type AssessmentSummary } from "../src/api/client.js";

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
  { id: 3, assessmentId: "a-juice", findingId: null, actor: "francesco", action: "import", field: "nmap", from: null, to: "4 created", reason: null, at },
];

/** A client that answers from the objects above, as the API would. */
export function fakeClient(overrides: Partial<ApiClient> = {}): ApiClient {
  const notFound = () => Promise.reject(new ApiError(404, "assessment not found"));
  return {
    mode: "api",
    listAssessments: async () => [juice, network],
    getAssessment: async (id) => (id === "a-juice" ? juiceDetail : notFound()),
    listAssets: async (id) => (id === "a-juice" ? juiceAssets : notFound()),
    listImports: async (id) => (id === "a-juice" ? juiceImports : notFound()),
    listAudit: async (id) => (id === "a-juice" ? juiceAudit : notFound()),
    ...overrides,
  };
}
