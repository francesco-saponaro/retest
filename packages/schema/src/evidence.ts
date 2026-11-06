import { z } from "zod";
import { SourceSchema } from "./source.js";

export const EVIDENCE_KINDS = ["request-response", "command-output", "scanner-output", "screenshot", "log", "note"] as const;

export const EvidenceKindSchema = z.enum(EVIDENCE_KINDS);
export type EvidenceKind = z.infer<typeof EvidenceKindSchema>;

/**
 * The proof behind a finding: a request and its response, the output of a command or a scanner,
 * a screenshot (as a description or a path), a log excerpt, or a note from the person testing.
 * `redacted` says whether secrets, tokens and personal data have been taken out; the report only
 * shows evidence that is redacted.
 */
export const EvidenceSchema = z.object({
  id: z.string().min(1),
  findingId: z.string().min(1).optional(),
  kind: EvidenceKindSchema,
  title: z.string().min(1).max(200).optional(),
  content: z.string().min(1),
  redacted: z.boolean().default(false),
  capturedAt: z.iso.datetime({ offset: true }).optional(),
  source: SourceSchema.optional(),
});

export type Evidence = z.infer<typeof EvidenceSchema>;
export type EvidenceInput = z.input<typeof EvidenceSchema>;
