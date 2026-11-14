import { z } from "zod";
import { CvssSchema, baseScore } from "./cvss.js";
import { EvidenceSchema } from "./evidence.js";
import { AsvsChapterIdSchema, CisControlNumberSchema, OwaspApiTop10IdSchema, OwaspTop10IdSchema } from "./mappings/index.js";
import { PhaseSchema } from "./phase.js";
import { SeveritySchema, severityFromScore } from "./severity.js";
import { SourceSchema } from "./source.js";

/**
 * The seven fields every finding must have, in the order the roadmap lists them. The UI shows
 * them in this order and the report prints them in this order.
 */
export const FINDING_FIELDS = [
  { key: "title", label: "Title", question: "What is the problem, precisely?" },
  { key: "asset", label: "Asset and scope", question: "Which application, host or endpoint is affected?" },
  { key: "impact", label: "Impact", question: "What can happen, and under which conditions?" },
  { key: "evidence", label: "Evidence", question: "Which requests, responses or screenshots prove it, with secrets removed?" },
  { key: "risk", label: "Risk", question: "How likely is it, how bad is it, and what is the CVSS score when one applies?" },
  { key: "fix", label: "Fix", question: "What concrete change removes it, and how can that change be checked?" },
  { key: "retest", label: "Retest", question: "What did the checks show after the fix?" },
] as const;

export type FindingFieldKey = (typeof FINDING_FIELDS)[number]["key"];

/**
 * What an import writes where a person has not written yet. A tool knows where a problem might be;
 * it does not know what can happen or what to change. The text says so, and the workflow refuses to
 * carry a finding to remediation while either field still holds it.
 */
export const UNASSESSED_IMPACT = "Not assessed yet. The scanner reported this; the impact is written after validation.";
export const UNWRITTEN_FIX = "Not written yet. The fix is decided after validation.";

export const LEVELS = ["low", "medium", "high"] as const;
export const LevelSchema = z.enum(LEVELS);
export type Level = z.infer<typeof LevelSchema>;

/**
 * Likelihood, impact and, when it applies, a CVSS vector with its score. A CVSS score is not
 * always possible (a missing log, a weak process), so severity is the one required part.
 * When there is a CVSS score, the severity must be the one its scale gives.
 */
export const RiskSchema = z
  .object({
    severity: SeveritySchema,
    likelihood: LevelSchema.optional(),
    impact: LevelSchema.optional(),
    cvss: CvssSchema.optional(),
  })
  .refine((r) => !r.cvss || severityFromScore(baseScore(r.cvss.vector)) === r.severity, {
    message: "severity does not match the CVSS score",
    path: ["severity"],
  });

export type Risk = z.infer<typeof RiskSchema>;

export const RETEST_OUTCOMES = ["pending", "fixed", "partially-fixed", "not-fixed"] as const;
export const RetestOutcomeSchema = z.enum(RETEST_OUTCOMES);
export type RetestOutcome = z.infer<typeof RetestOutcomeSchema>;

/** The outcome of the checks run after the fix. Anything other than "pending" needs a date. */
export const RetestSchema = z
  .object({
    outcome: RetestOutcomeSchema,
    testedAt: z.iso.datetime({ offset: true }).optional(),
    notes: z.string().optional(),
  })
  .refine((r) => r.outcome === "pending" || r.testedAt !== undefined, {
    message: "a retest that has happened needs a testedAt date",
    path: ["testedAt"],
  });

export type Retest = z.infer<typeof RetestSchema>;

/** `CVE-2015-9235`: the canonical spelling, upper case, four-digit year, at least four digits after it. */
export const CveIdSchema = z.string().regex(/^CVE-\d{4}-\d{4,}$/, "not a CVE id");

/**
 * Where the finding sits in each standard, plus the CVE ids it refers to. All arrays, because a
 * weakness can touch several. CWE and CVE come from the tools; the rest is filled from the CWE
 * table once the finding is classified.
 */
export const MappingsSchema = z.object({
  cwe: z.array(z.number().int().positive()).default([]),
  cve: z.array(CveIdSchema).default([]),
  owaspTop10: z.array(OwaspTop10IdSchema).default([]),
  owaspApi: z.array(OwaspApiTop10IdSchema).default([]),
  asvs: z.array(AsvsChapterIdSchema).default([]),
  cis: z.array(CisControlNumberSchema).default([]),
});

export type Mappings = z.infer<typeof MappingsSchema>;

export const FINDING_STATUSES = ["open", "false-positive", "accepted-risk", "closed"] as const;
export const FindingStatusSchema = z.enum(FINDING_STATUSES);
export type FindingStatus = z.infer<typeof FindingStatusSchema>;

const datetime = z.iso.datetime({ offset: true });

/**
 * One finding. The seven roadmap fields are title, assetId + scope, impact, evidence, risk,
 * fix and retest. The rest is bookkeeping: which assessment it belongs to, which phase it is in,
 * its status, which tools reported it and how it maps to the standards.
 */
export const FindingSchema = z
  .object({
    id: z.string().min(1),
    assessmentId: z.string().min(1),

    // 1. Title
    title: z.string().min(1).max(200),
    // 2. Asset and scope
    assetId: z.string().min(1),
    /** The part of the asset: an endpoint, a port, a file path, a resource name. */
    scope: z.string().min(1).max(500),
    // 3. Impact
    impact: z.string().min(1),
    // 4. Evidence
    evidence: z.array(EvidenceSchema).default([]),
    // 5. Risk
    risk: RiskSchema,
    // 6. Fix
    fix: z.string().min(1),
    // 7. Retest
    retest: RetestSchema.optional(),

    phase: PhaseSchema.default("assessment"),
    status: FindingStatusSchema.default("open"),
    falsePositiveReason: z.string().min(1).optional(),
    sources: z.array(SourceSchema).default([]),
    mappings: MappingsSchema.default({ cwe: [], cve: [], owaspTop10: [], owaspApi: [], asvs: [], cis: [] }),
    createdAt: datetime,
    updatedAt: datetime,
  })
  .refine((f) => f.status !== "false-positive" || f.falsePositiveReason !== undefined, {
    message: "a false positive needs a reason",
    path: ["falsePositiveReason"],
  })
  .refine((f) => f.status !== "closed" || f.retest?.outcome === "fixed", {
    message: "a finding is closed only when the retest says it is fixed",
    path: ["status"],
  });

export type Finding = z.infer<typeof FindingSchema>;
export type FindingInput = z.input<typeof FindingSchema>;

/** Build a finding now, with the timestamps set and the defaults filled. */
export function newFinding(input: Omit<FindingInput, "createdAt" | "updatedAt">, now: Date = new Date()): Finding {
  const stamp = now.toISOString();
  return FindingSchema.parse({ ...input, createdAt: stamp, updatedAt: stamp });
}
