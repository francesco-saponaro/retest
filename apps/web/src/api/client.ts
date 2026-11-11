import type { Asset, Finding, OwaspTop10Id, Phase, Risk, Severity, Tool } from "@retest/schema";
import type { AssessmentOut, AuditLine, FindingSummary, ImportOut } from "@retest/api/rows.js";
import type { Totals } from "@retest/api/services/assessments.js";
import type { FindingDetail } from "@retest/api/services/findings.js";

/**
 * What the web app asks of the API. There are two implementations with the same contract: `http.ts`
 * talks to `apps/api` over HTTP, and `demo.ts` runs the API's own services in the browser against
 * PostgreSQL compiled to WebAssembly. The screens cannot tell them apart, which is the point.
 */
export type AssessmentSummary = AssessmentOut;
export type AssessmentDetail = AssessmentOut & { totals: Totals };

/** The findings table's filters: one value each, matched the way the API matches them. `q` is searched in the title and the scope. */
export interface FindingFilter {
  severity?: Severity;
  tool?: Tool;
  phase?: Phase;
  owasp?: OwaspTop10Id;
  assetId?: string;
  q?: string;
}

/** One page of findings, most severe first, with the total that matched the filters. */
export interface FindingsPage {
  items: FindingSummary[];
  total: number;
  limit: number;
  offset: number;
}

/** What a screen may change on a finding tonight: its risk. The workflow (phase, status, retest) has its own calls. */
export interface FindingPatch {
  risk?: Risk;
}

/** The API answers at most this many findings per page; the table asks for all of them at once. */
export const PAGE = 500;

export interface ApiClient {
  /** `demo` when the data lives in the browser and goes away with the tab. */
  mode: "demo" | "api";
  listAssessments(): Promise<AssessmentSummary[]>;
  getAssessment(id: string): Promise<AssessmentDetail>;
  listAssets(id: string): Promise<Asset[]>;
  listImports(id: string): Promise<ImportOut[]>;
  listAudit(id: string): Promise<AuditLine[]>;
  listFindings(id: string, filter: FindingFilter): Promise<FindingsPage>;
  getFinding(fid: string): Promise<FindingDetail>;
  updateFinding(fid: string, patch: FindingPatch): Promise<Finding>;
}

/** The API said no. `status` is the HTTP status and `message` the API's own one-line reason. */
export class ApiError extends Error {
  override name = "ApiError";
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export type { Asset, AuditLine, Finding, FindingDetail, FindingSummary, ImportOut, Totals };
