import type { Severity } from "@retest/schema";
import { z } from "zod";
import type { ParseResult, RawFinding } from "./raw.js";

/**
 * Semgrep's SARIF output (`semgrep scan --sarif`). SARIF is the OASIS interchange format for
 * static-analysis results, so this reader is written against SARIF 2.1.0 and takes Semgrep's
 * conventions where SARIF leaves room: the CWE and OWASP tags on a rule, the precision, the
 * match-based fingerprint. A result is a rule matching a region of a file; it is a pattern match,
 * and whether the matched code is reachable with attacker input is for validation to say.
 */

const MessageSchema = z.object({ text: z.string().optional(), markdown: z.string().optional() }).loose();

const RuleSchema = z
  .object({
    id: z.string().min(1),
    name: z.string().optional(),
    shortDescription: MessageSchema.optional(),
    fullDescription: MessageSchema.optional(),
    help: MessageSchema.optional(),
    helpUri: z.string().optional(),
    defaultConfiguration: z.object({ level: z.string().optional() }).loose().optional(),
    properties: z
      .object({
        tags: z.array(z.string()).optional(),
        precision: z.string().optional(),
      })
      .loose()
      .optional(),
  })
  .loose();

const LocationSchema = z
  .object({
    physicalLocation: z
      .object({
        artifactLocation: z.object({ uri: z.string().optional(), uriBaseId: z.string().optional() }).loose().optional(),
        region: z
          .object({
            startLine: z.number().int().optional(),
            endLine: z.number().int().optional(),
            startColumn: z.number().int().optional(),
            endColumn: z.number().int().optional(),
            snippet: z.object({ text: z.string().optional() }).loose().optional(),
          })
          .loose()
          .optional(),
      })
      .loose()
      .optional(),
  })
  .loose();

const ResultSchema = z
  .object({
    ruleId: z.string().min(1),
    ruleIndex: z.number().int().optional(),
    level: z.string().optional(),
    message: MessageSchema,
    locations: z.array(LocationSchema).default([]),
    fingerprints: z.record(z.string(), z.string()).optional(),
    properties: z.record(z.string(), z.unknown()).optional(),
  })
  .loose();

const RunSchema = z
  .object({
    tool: z
      .object({
        driver: z
          .object({
            name: z.string().min(1),
            version: z.string().optional(),
            semanticVersion: z.string().optional(),
            informationUri: z.string().optional(),
            rules: z.array(RuleSchema).default([]),
          })
          .loose(),
      })
      .loose(),
    results: z.array(ResultSchema).default([]),
  })
  .loose();

const LogSchema = z
  .object({
    version: z.literal("2.1.0"),
    runs: z.array(RunSchema).min(1),
  })
  .loose();

export type SarifLevel = "error" | "warning" | "note" | "none";

export interface SarifRule {
  id: string;
  name: string;
  level: SarifLevel;
  description: string;
  helpUri?: string;
  tags: string[];
  /** From tags like `CWE-89: ...`. */
  cwe: number[];
  /** From tags like `OWASP-A03:2021 - Injection`, as `A03:2021`. */
  owasp: string[];
  precision?: string;
  /** Links from the help text's "References" list. */
  references: string[];
}

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: string;
  file?: string;
  startLine?: number;
  endLine?: number;
  snippet?: string;
  fingerprint?: string;
}

export interface SarifRun {
  tool: { name: string; version?: string };
  rules: SarifRule[];
  results: SarifResult[];
}

export interface SarifLog {
  version: string;
  runs: SarifRun[];
}

const LEVELS: readonly SarifLevel[] = ["error", "warning", "note", "none"];

function toLevel(value: string | undefined, fallback: SarifLevel): SarifLevel {
  return value && (LEVELS as readonly string[]).includes(value) ? (value as SarifLevel) : fallback;
}

function cweTags(tags: string[]): number[] {
  const out: number[] = [];
  for (const tag of tags) {
    const m = /^CWE-(\d+)/i.exec(tag);
    if (m) out.push(Number(m[1]));
  }
  return [...new Set(out)];
}

function owaspTags(tags: string[]): string[] {
  const out: string[] = [];
  for (const tag of tags) {
    const m = /^OWASP-(A\d{2}:\d{4})/i.exec(tag);
    if (m) out.push(m[1]!.toUpperCase());
  }
  return out;
}

function linksIn(text: string | undefined): string[] {
  if (!text) return [];
  const out = new Set<string>();
  for (const m of text.matchAll(/https?:\/\/[^\s)\]]+/g)) out.add(m[0]);
  return [...out];
}

function toRule(r: z.infer<typeof RuleSchema>): SarifRule {
  const tags = r.properties?.tags ?? [];
  const rule: SarifRule = {
    id: r.id,
    name: r.name ?? r.id,
    level: toLevel(r.defaultConfiguration?.level, "warning"),
    description: (r.fullDescription?.text ?? r.shortDescription?.text ?? "").trim(),
    tags,
    cwe: cweTags(tags),
    owasp: owaspTags(tags),
    references: linksIn(r.help?.text),
  };
  if (r.helpUri) rule.helpUri = r.helpUri;
  if (r.properties?.precision) rule.precision = r.properties.precision;
  return rule;
}

function toResult(r: z.infer<typeof ResultSchema>, rules: Map<string, SarifRule>): SarifResult {
  const rule = rules.get(r.ruleId);
  const result: SarifResult = {
    ruleId: r.ruleId,
    level: toLevel(r.level, rule?.level ?? "warning"),
    message: (r.message.text ?? r.message.markdown ?? "").trim(),
  };
  const physical = r.locations[0]?.physicalLocation;
  const file = physical?.artifactLocation?.uri;
  if (file) result.file = file;
  const region = physical?.region;
  if (region?.startLine !== undefined) result.startLine = region.startLine;
  if (region?.endLine !== undefined) result.endLine = region.endLine;
  if (region?.snippet?.text) result.snippet = region.snippet.text;
  const fingerprint = r.fingerprints?.["matchBasedId/v1"] ?? Object.values(r.fingerprints ?? {})[0];
  if (fingerprint) result.fingerprint = fingerprint;
  return result;
}

/** Parse a SARIF 2.1.0 log. Throws when the text is not one. */
export function parseSarif(text: string): SarifLog {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error("not JSON");
  }
  const parsed = LogSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`not a SARIF log${issue ? ` (${issue.path.join(".") || "root"}: ${issue.message})` : ""}`);
  }
  return {
    version: parsed.data.version,
    runs: parsed.data.runs.map((run) => {
      const rules = run.tool.driver.rules.map(toRule);
      const byId = new Map(rules.map((r) => [r.id, r]));
      const tool: SarifRun["tool"] = { name: run.tool.driver.name };
      const version = run.tool.driver.semanticVersion ?? run.tool.driver.version;
      if (version) tool.version = version;
      return { tool, rules, results: run.results.map((r) => toResult(r, byId)) };
    }),
  };
}

export interface SemgrepOptions {
  /** What to call the code that was scanned. SARIF does not say; the CLI and the API pass it in. */
  repository?: string;
}

/** The repository name used when none is given. */
export const UNNAMED_REPOSITORY = "source";

/**
 * SARIF's level is about how sure the rule is and how much the author wants it seen, not about
 * impact. It is kept as the tool's own rating: error high, warning medium, note low.
 */
const LEVEL_SEVERITY: Record<SarifLevel, Severity> = { error: "high", warning: "medium", note: "low", none: "info" };

function lines(r: SarifResult): string {
  if (r.startLine === undefined) return "";
  return r.endLine !== undefined && r.endLine !== r.startLine ? `${r.startLine}-${r.endLine}` : String(r.startLine);
}

/**
 * One raw finding per result, on the repository, at `file:lines`. The rule's CWE is the
 * weakness; the message is the description; there is no fix, because a Semgrep message says what
 * the pattern means, not what to change in this file.
 */
export function semgrepFindings(log: SarifLog, options: SemgrepOptions = {}): RawFinding[] {
  const repository = options.repository ?? UNNAMED_REPOSITORY;
  const out: RawFinding[] = [];
  for (const run of log.runs) {
    const rules = new Map(run.rules.map((r) => [r.id, r]));
    for (const r of run.results) {
      if (!r.file) continue;
      const rule = rules.get(r.ruleId);
      const where = lines(r);
      const shortName = r.ruleId.split(".").pop() ?? r.ruleId;
      const finding: RawFinding = {
        tool: "semgrep",
        rawId: `${r.ruleId}@${r.file}${r.startLine !== undefined ? `:${r.startLine}` : ""}`,
        title: `${shortName} in ${r.file}`,
        severity: LEVEL_SEVERITY[r.level],
        repository,
        filePath: r.file,
        scope: where ? `${r.file}:${where}` : r.file,
        cwe: rule?.cwe ?? [],
        cve: [],
        references: [...(rule?.helpUri ? [rule.helpUri] : []), ...(rule?.references ?? [])],
        evidence: r.snippet ? [{ kind: "scanner-output", title: where ? `${r.file}:${where}` : r.file, content: r.snippet.trim() }] : [],
        tags: [
          ...(rule?.tags.filter((t) => !/^(CWE-|OWASP-)/i.test(t)) ?? []),
          ...(rule?.owasp.map((o) => `owasp:${o}`) ?? []),
          ...(rule?.precision ? [`semgrep-precision:${rule.precision}`] : []),
        ],
        phase: "assessment",
      };
      const description = r.message || rule?.description;
      if (description) finding.description = description;
      out.push(finding);
    }
  }
  return out;
}

/** Parse a whole SARIF file from Semgrep. Results without a location are reported and skipped. */
export function parseSemgrep(text: string, options: SemgrepOptions = {}): ParseResult & { log: SarifLog } {
  const log = parseSarif(text);
  const warnings: string[] = [];
  for (const run of log.runs) {
    run.results.forEach((r, i) => {
      if (!r.file) warnings.push(`result ${i + 1} (${r.ruleId}) has no location; skipped`);
    });
  }
  return { tool: "semgrep", log, findings: semgrepFindings(log, options), warnings };
}
