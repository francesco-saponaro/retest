import { z } from "zod";

/** The tools whose output Retest can import, plus "manual" for things found by hand. */
export const TOOLS = ["nmap", "nuclei", "zap", "semgrep", "trivy", "prowler", "manual"] as const;

export const ToolSchema = z.enum(TOOLS);
export type Tool = z.infer<typeof ToolSchema>;

/**
 * Where a finding came from: the tool and the id that tool gave it (a ZAP plugin id, a Nuclei
 * template id, a Semgrep rule id, a Trivy vulnerability id, a Prowler check id, an Nmap port).
 * One finding can have several sources once the same issue is seen by several tools.
 */
export const SourceSchema = z.object({
  tool: ToolSchema,
  rawId: z.string().min(1),
  /** A link to the tool's own page for this check, when it has one. */
  reference: z.url().optional(),
});

export type Source = z.infer<typeof SourceSchema>;
