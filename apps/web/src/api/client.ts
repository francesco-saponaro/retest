import type { Asset, Evidence, EvidenceKind, Finding, FindingStatus, OwaspTop10Id, Phase, RetestOutcome, Risk, Severity, Tool } from "@retest/schema";
import type { AssessmentOut, AuditLine, FindingSummary, ImportOut } from "@retest/api/rows.js";
import type { Totals } from "@retest/api/services/assessments.js";
import type { FindingDetail } from "@retest/api/services/findings.js";
import type { Report } from "@retest/api/report/model.js";

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

/** What a person writes on a finding: the risk from the calculator, the impact and the fix in words. The workflow (phase, status, retest) has its own calls. */
export interface FindingPatch {
  risk?: Risk;
  impact?: string;
  fix?: string;
}

/** A move through the phases. The reason is optional forward and required back; the API says so when it is missing. */
export interface PhaseChange {
  phase: Phase;
  reason?: string;
}

/** Setting a finding aside, or taking it back. "closed" is refused: the retest closes. */
export interface StatusChange {
  status: FindingStatus;
  reason?: string;
}

/** A retest that happened: its outcome and what the checks showed. `testedAt` is now when left out. */
export interface RetestInput {
  outcome: RetestOutcome;
  notes: string;
  testedAt?: string;
}

/** A piece of evidence a person captured. */
export interface NewEvidence {
  kind: EvidenceKind;
  title?: string;
  content: string;
  redacted?: boolean;
}

export interface EvidencePatch {
  title?: string;
  content?: string;
  redacted?: boolean;
}

/** The two documents an assessment produces, as markdown files: the technical report and the executive summary. */
export type ReportKind = "report" | "summary";

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
  setFindingPhase(fid: string, change: PhaseChange): Promise<Finding>;
  setFindingStatus(fid: string, change: StatusChange): Promise<Finding>;
  recordRetest(fid: string, input: RetestInput): Promise<Finding>;
  addEvidence(fid: string, input: NewEvidence): Promise<Evidence>;
  updateEvidence(eid: string, patch: EvidencePatch): Promise<Evidence>;
  listFindingAudit(fid: string): Promise<AuditLine[]>;
  /** The report model both documents are rendered from. */
  getReport(id: string): Promise<Report>;
  /** One of the two documents as markdown, for download. */
  getReportMarkdown(id: string, kind: ReportKind): Promise<string>;
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

export type { Asset, AuditLine, Evidence, Finding, FindingDetail, FindingSummary, ImportOut, Report, Totals };
