import { SEVERITIES, type Severity } from "@retest/schema";
import { z } from "zod";
import type { ParseResult, RawEvidence, RawFinding } from "./raw.js";

/**
 * Nuclei's JSON Lines output (`-jsonl`, or `-je file`). One line per match: which template
 * matched, where, and the request and response that proved it. A template is a YAML file that
 * says what to send and what in the answer counts as a match, so a line is only as good as its
 * matcher; the `matcher-name` says which one fired.
 */

const stringOrList = z.union([z.string(), z.array(z.string())]).transform((v) => (Array.isArray(v) ? v : [v]));

const ClassificationSchema = z
  .object({
    "cwe-id": stringOrList.optional(),
    "cve-id": stringOrList.optional(),
    "cvss-metrics": z.string().optional(),
    "cvss-score": z.number().optional(),
  })
  .loose();

const LineSchema = z
  .object({
    "template-id": z.string().min(1, "missing template-id"),
    template: z.string().optional(),
    "template-url": z.string().optional(),
    "template-path": z.string().optional(),
    info: z
      .object({
        name: z.string().min(1),
        author: stringOrList.optional(),
        tags: stringOrList.optional(),
        description: z.string().optional(),
        reference: stringOrList.nullable().optional(),
        severity: z.string().optional(),
        classification: ClassificationSchema.optional(),
        remediation: z.string().optional(),
      })
      .loose(),
    "matcher-name": z.string().optional(),
    "extracted-results": z.array(z.string()).optional(),
    type: z.string().optional(),
    host: z.string().optional(),
    ip: z.string().optional(),
    port: z.union([z.string(), z.number()]).optional(),
    scheme: z.string().optional(),
    url: z.string().optional(),
    "matched-at": z.string().min(1, "missing matched-at"),
    request: z.string().optional(),
    response: z.string().optional(),
    "curl-command": z.string().optional(),
    timestamp: z.string().optional(),
  })
  .loose();

export interface NucleiClassification {
  cweIds: string[];
  cveIds: string[];
  cvssMetrics?: string;
  cvssScore?: number;
}

export interface NucleiResult {
  templateId: string;
  templatePath?: string;
  templateUrl?: string;
  name: string;
  authors: string[];
  tags: string[];
  description?: string;
  references: string[];
  /** Nuclei's own rating. `unknown` becomes `info`. */
  severity: Severity;
  classification?: NucleiClassification;
  remediation?: string;
  /** Which matcher in the template fired, when the template has more than one. */
  matcherName?: string;
  extractedResults: string[];
  /** The protocol of the template: http, dns, tcp, ssl, ... */
  type: string;
  host: string;
  ip?: string;
  port?: number;
  scheme?: string;
  matchedAt: string;
  request?: string;
  response?: string;
  curlCommand?: string;
  timestamp?: string;
}

/**
 * Nuclei writes null for the fields a template leaves empty ("cve-id": null, "description": null),
 * which means the same as the field not being there. Dropping them first keeps the schema simple.
 */
function withoutNulls(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(withoutNulls);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== null).map(([k, v]) => [k, withoutNulls(v)]));
  }
  return value;
}

/** Parse one line of output. Throws with a reason when the line is not a result. */
export function parseNucleiLine(line: string): NucleiResult {
  let json: unknown;
  try {
    json = JSON.parse(line);
  } catch {
    throw new Error("not JSON");
  }
  const parsed = LineSchema.safeParse(withoutNulls(json));
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(issue ? `${issue.path.join(".") || "line"}: ${issue.message}` : "not a Nuclei result");
  }
  const r = parsed.data;
  const info = r.info;
  const result: NucleiResult = {
    templateId: r["template-id"],
    name: info.name,
    authors: info.author ?? [],
    tags: info.tags ?? [],
    references: info.reference ?? [],
    severity: toSeverity(info.severity),
    extractedResults: r["extracted-results"] ?? [],
    type: r.type ?? "http",
    host: r.host ?? r["matched-at"],
    matchedAt: r["matched-at"],
  };
  if (r.template) result.templatePath = r.template;
  if (r["template-url"]) result.templateUrl = r["template-url"];
  if (info.description) result.description = info.description;
  if (info.remediation) result.remediation = info.remediation;
  if (info.classification) {
    const c = info.classification;
    const classification: NucleiClassification = { cweIds: c["cwe-id"] ?? [], cveIds: c["cve-id"] ?? [] };
    if (c["cvss-metrics"]) classification.cvssMetrics = c["cvss-metrics"];
    if (c["cvss-score"] !== undefined) classification.cvssScore = c["cvss-score"];
    result.classification = classification;
  }
  if (r["matcher-name"]) result.matcherName = r["matcher-name"];
  if (r.ip) result.ip = r.ip;
  const port = r.port !== undefined ? Number(r.port) : portOf(r["matched-at"]);
  if (port !== undefined && Number.isInteger(port) && port > 0) result.port = port;
  if (r.scheme) result.scheme = r.scheme;
  if (r.request) result.request = r.request;
  if (r.response) result.response = r.response;
  if (r["curl-command"]) result.curlCommand = r["curl-command"];
  if (r.timestamp) result.timestamp = r.timestamp;
  return result;
}

function toSeverity(value: string | undefined): Severity {
  const v = (value ?? "").toLowerCase();
  return (SEVERITIES as readonly string[]).includes(v) ? (v as Severity) : "info";
}

function parseUrl(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

function portOf(matchedAt: string): number | undefined {
  const u = parseUrl(matchedAt);
  if (!u) return undefined;
  if (u.port) return Number(u.port);
  if (u.protocol === "https:") return 443;
  if (u.protocol === "http:") return 80;
  return undefined;
}

function hostOf(result: NucleiResult): string | undefined {
  return parseUrl(result.matchedAt)?.hostname || result.ip || parseUrl(result.host)?.hostname || undefined;
}

/** `GET /api-docs/`: the method of the request that matched and the path (with its query) that answered. */
function scopeOf(result: NucleiResult): string {
  const method = result.request?.match(/^([A-Z]+) /)?.[1] ?? "GET";
  const u = parseUrl(result.matchedAt);
  const path = u ? `${u.pathname}${u.search}` : result.matchedAt;
  return `${method} ${path}`;
}

function cweNumbers(ids: string[]): number[] {
  return ids.map((id) => Number(id.replace(/^CWE-/i, ""))).filter((n) => Number.isInteger(n) && n > 0);
}

/** One raw finding per result. Nuclei's severity, CWE, CVSS and remediation are kept as the tool's word, nothing more. */
export function nucleiFindings(results: NucleiResult[]): RawFinding[] {
  return results.map((r) => {
    const evidence: RawEvidence[] = [];
    if (r.request || r.response) {
      evidence.push({
        kind: "request-response",
        title: `${scopeOf(r).split(" ")[0]} ${r.matchedAt}`,
        content: [r.request, r.response].filter((s): s is string => s !== undefined).join("\n"),
      });
    }
    if (r.extractedResults.length > 0) {
      evidence.push({ kind: "scanner-output", title: `Extracted by ${r.templateId}`, content: r.extractedResults.join("\n") });
    }
    const finding: RawFinding = {
      tool: "nuclei",
      rawId: r.matcherName ? `${r.templateId}:${r.matcherName}` : r.templateId,
      title: r.matcherName ? `${r.name}: ${r.matcherName}` : r.name,
      severity: r.severity,
      url: r.matchedAt,
      scope: scopeOf(r),
      cwe: cweNumbers(r.classification?.cweIds ?? []),
      cve: r.classification?.cveIds ?? [],
      references: [...(r.templateUrl ? [r.templateUrl] : []), ...r.references],
      evidence,
      tags: [...r.tags],
      phase: "assessment",
    };
    const host = hostOf(r);
    if (host) finding.host = host;
    if (r.port !== undefined) {
      finding.port = r.port;
      finding.protocol = "tcp";
    }
    if (r.description) finding.description = r.description;
    if (r.remediation) finding.fix = r.remediation;
    if (r.classification?.cvssMetrics || r.classification?.cvssScore !== undefined) {
      finding.cvss = {
        ...(r.classification.cvssMetrics ? { vector: r.classification.cvssMetrics } : {}),
        ...(r.classification.cvssScore !== undefined ? { score: r.classification.cvssScore } : {}),
      };
    }
    if (r.timestamp) finding.detectedAt = r.timestamp;
    return finding;
  });
}

/** Parse a whole JSONL file. Bad lines are skipped and reported by line number; blank lines are ignored. */
export function parseNuclei(text: string): ParseResult & { results: NucleiResult[] } {
  const results: NucleiResult[] = [];
  const warnings: string[] = [];
  text.split(/\r?\n/).forEach((line, index) => {
    if (line.trim() === "") return;
    try {
      results.push(parseNucleiLine(line));
    } catch (error) {
      warnings.push(`line ${index + 1}: ${error instanceof Error ? error.message : String(error)}`);
    }
  });
  return { tool: "nuclei", results, findings: nucleiFindings(results), warnings };
}
