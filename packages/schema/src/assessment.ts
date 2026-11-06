import { z } from "zod";
import { PhaseSchema } from "./phase.js";

const datetime = z.iso.datetime({ offset: true });

/**
 * Phase 1 in writing: what may be tested, what may not, who said so and when.
 * Nothing in Retest should be imported against an assessment without a scope.
 */
export const ScopeSchema = z
  .object({
    /** Hosts, networks, URLs or repositories, as written in the authorisation. */
    targets: z.array(z.string().min(1)).min(1),
    exclusions: z.array(z.string().min(1)).default([]),
    authorizedBy: z.string().min(1),
    authorizedAt: datetime.optional(),
    startsAt: datetime.optional(),
    endsAt: datetime.optional(),
  })
  .refine((s) => !s.startsAt || !s.endsAt || s.startsAt <= s.endsAt, {
    message: "the window ends before it starts",
    path: ["endsAt"],
  });

export type Scope = z.infer<typeof ScopeSchema>;

export const ASSESSMENT_STATUSES = ["draft", "active", "closed"] as const;
export const AssessmentStatusSchema = z.enum(ASSESSMENT_STATUSES);
export type AssessmentStatus = z.infer<typeof AssessmentStatusSchema>;

/** One engagement: a scope, a set of assets, the findings against them, and the phase the work is in. */
export const AssessmentSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1).max(200),
  client: z.string().min(1).optional(),
  scope: ScopeSchema,
  phase: PhaseSchema.default("scope"),
  status: AssessmentStatusSchema.default("draft"),
  createdAt: datetime,
  updatedAt: datetime,
});

export type Assessment = z.infer<typeof AssessmentSchema>;
export type AssessmentInput = z.input<typeof AssessmentSchema>;
