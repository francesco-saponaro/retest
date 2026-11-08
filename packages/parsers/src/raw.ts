import type { EvidenceKind, Phase, Severity, Tool } from "@retest/schema";

/** A piece of proof as the tool gave it: the port line, a script's output, a request and its response. */
export interface RawEvidence {
  kind: EvidenceKind;
  title?: string;
  content: string;
}

/**
 * What a parser gets out of one scanner result, before it becomes a Finding.
 *
 * It keeps what the tool said and nothing the tool did not say: a severity only when the tool
 * rates its own results, a CVSS vector only when the tool gives one, an impact and a fix only
 * when the tool wrote them. `normalize()` turns this into a Finding and fills the gaps with
 * honest placeholders; `classify()` (stage 3) scores it and maps it to the standards.
 */
export interface RawFinding {
  tool: Tool;
  /** The tool's own id for this result: a port, a template id, a plugin id. Unique within one run. */
  rawId: string;
  title: string;
  /** The tool's rating, when it has one. Nmap does not rate; Nuclei does. */
  severity?: Severity;

  /** Where it is. A host and a port for a network finding, a URL for a web finding; both when both are known. */
  host?: string;
  /** A name for the host when the tool resolved one. */
  hostname?: string;
  port?: number;
  protocol?: "tcp" | "udp";
  url?: string;
  /** A code finding: the repository it was found in, and the file. */
  repository?: string;
  filePath?: string;
  /** A container-image finding: the image as the tool names it, `bkimminich/juice-shop:v17.1.1`. */
  image?: string;
  /** A cloud finding: the account and, when there is one, the resource. */
  cloud?: {
    provider: string;
    account: string;
    accountName?: string;
    region?: string;
    resource?: string;
    resourceType?: string;
  };
  /** The part of the asset the finding is about: `tcp/3000`, `GET /api-docs/`, `routes/login.ts:34`. Becomes the finding's scope. */
  scope: string;

  /** What the tool says the check is about. Not an impact statement. */
  description?: string;
  impact?: string;
  fix?: string;

  cwe: number[];
  cve: string[];
  cvss?: { vector?: string; score?: number };
  /** Links: the tool's page for the check first, then whatever the check cites. */
  references: string[];
  evidence: RawEvidence[];
  tags: string[];
  /** When the tool saw it, ISO 8601 with an offset. */
  detectedAt?: string;
  /** Which phase the result belongs to. An inventory line is recon; a candidate problem is assessment. */
  phase?: Phase;
}

/** What every `parse<Tool>()` returns. Warnings are for lines or hosts that were skipped, never for a parse that failed. */
export interface ParseResult {
  tool: Tool;
  findings: RawFinding[];
  warnings: string[];
}
