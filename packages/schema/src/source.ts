import { z } from "zod";
import { SeveritySchema } from "./severity.js";

/** The tools whose output Retest can import, plus "manual" for things found by hand. */
export const TOOLS = ["nmap", "nuclei", "zap", "semgrep", "trivy", "prowler", "manual"] as const;

export const ToolSchema = z.enum(TOOLS);
export type Tool = z.infer<typeof ToolSchema>;

/**
 * What a tool said the risk was, kept word for word. The vector is not validated here and the
 * score is not checked against it: this is the tool's claim, and `classify()` is where it is
 * verified before anything goes into the finding's own `risk`.
 */
export const SourceRatingSchema = z.object({
  vector: z.string().min(1).optional(),
  score: z.number().min(0).max(10).optional(),
});

export type SourceRating = z.infer<typeof SourceRatingSchema>;

/**
 * Where a finding came from: the tool and the id that tool gave it (a ZAP plugin id, a Nuclei
 * template id, a Semgrep rule id, a Trivy vulnerability id, a Prowler check id, an Nmap port).
 * One finding can have several sources once the same issue is seen by several tools, and each
 * source keeps its own rating, so the record of what each tool said survives deduplication.
 */
export const SourceSchema = z.object({
  tool: ToolSchema,
  rawId: z.string().min(1),
  /** A link to the tool's own page for this check, when it has one. */
  reference: z.url().optional(),
  /** The tool's own severity word, when it rates its results. */
  severity: SeveritySchema.optional(),
  /** The tool's CVSS claim: a vector, a score, or both. */
  cvss: SourceRatingSchema.optional(),
});

export type Source = z.infer<typeof SourceSchema>;
