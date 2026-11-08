import type { Tool } from "@retest/schema";
import { parseNmap } from "./nmap.js";
import { parseNuclei } from "./nuclei.js";
import { parseProwler } from "./prowler.js";
import type { ParseResult } from "./raw.js";
import { parseSemgrep, type SemgrepOptions } from "./semgrep.js";
import { parseTrivy } from "./trivy.js";
import { parseZap } from "./zap.js";

export type { ParseResult, RawEvidence, RawFinding } from "./raw.js";
export { nmapFindings, parseNmap, parseNmapXml, portLine } from "./nmap.js";
export type { NmapHost, NmapPort, NmapScan, NmapScript, NmapService, PortState, ScriptValue, ScriptValues } from "./nmap.js";
export { nucleiFindings, parseNuclei, parseNucleiLine } from "./nuclei.js";
export type { NucleiClassification, NucleiResult } from "./nuclei.js";
export { parseZap, parseZapReport, zapFindings } from "./zap.js";
export type { ZapAlert, ZapConfidence, ZapInstance, ZapReport, ZapSite } from "./zap.js";
export { UNNAMED_REPOSITORY, parseSarif, parseSemgrep, semgrepFindings } from "./semgrep.js";
export type { SarifLevel, SarifLog, SarifResult, SarifRule, SarifRun, SemgrepOptions } from "./semgrep.js";
export { parseTrivy, parseTrivyReport, trivyFindings } from "./trivy.js";
export type { TrivyCvss, TrivyReport, TrivyResult, TrivyVulnerability } from "./trivy.js";
export { parseProwler, parseProwlerOcsf, prowlerFindings } from "./prowler.js";
export type { ProwlerCheck, ProwlerStatus } from "./prowler.js";
export { UNASSESSED_IMPACT, UNWRITTEN_FIX, findingId, normalize } from "./normalize.js";
export type { NormalizeOptions, Normalized } from "./normalize.js";
export { dedupe, fingerprint, normalizeScope } from "./dedupe.js";
export type { DedupeOptions, Deduped, Merge } from "./dedupe.js";
export { CLOUD_CHECKS, classify, cloudCheckCwes } from "./classify.js";
export type { Classified, ClassifyOptions, CloudCheck } from "./classify.js";
export { decodeEntities, stripHtml } from "./text.js";

/** What a parser can be told. Only Semgrep needs anything: SARIF does not name the repository. */
export type ParseOptions = SemgrepOptions;

const PARSERS: Partial<Record<Tool, (text: string, options: ParseOptions) => ParseResult>> = {
  nmap: (text) => parseNmap(text),
  nuclei: (text) => parseNuclei(text),
  zap: (text) => parseZap(text),
  semgrep: (text, options) => parseSemgrep(text, options),
  trivy: (text) => parseTrivy(text),
  prowler: (text) => parseProwler(text),
};

/** The tools whose output can be imported. */
export const PARSEABLE_TOOLS = Object.keys(PARSERS) as Tool[];

export function canParse(tool: Tool): boolean {
  return tool in PARSERS;
}

/** Parse a scanner's output by tool name. Throws when the tool has no parser. */
export function parse(tool: Tool, text: string, options: ParseOptions = {}): ParseResult {
  const parser = PARSERS[tool];
  if (!parser) throw new Error(`no parser for ${tool}`);
  return parser(text, options);
}
