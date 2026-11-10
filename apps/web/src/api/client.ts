import type { Asset } from "@retest/schema";
import type { AssessmentOut, AuditLine, ImportOut } from "@retest/api/rows.js";
import type { Totals } from "@retest/api/services/assessments.js";

/**
 * What the web app asks of the API. There are two implementations with the same contract: `http.ts`
 * talks to `apps/api` over HTTP, and `demo.ts` runs the API's own services in the browser against
 * PostgreSQL compiled to WebAssembly. The screens cannot tell them apart, which is the point.
 */
export type AssessmentSummary = AssessmentOut;
export type AssessmentDetail = AssessmentOut & { totals: Totals };

export interface ApiClient {
  /** `demo` when the data lives in the browser and goes away with the tab. */
  mode: "demo" | "api";
  listAssessments(): Promise<AssessmentSummary[]>;
  getAssessment(id: string): Promise<AssessmentDetail>;
  listAssets(id: string): Promise<Asset[]>;
  listImports(id: string): Promise<ImportOut[]>;
  listAudit(id: string): Promise<AuditLine[]>;
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

export type { Asset, AuditLine, ImportOut, Totals };
