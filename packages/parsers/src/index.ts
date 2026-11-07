import type { Tool } from "@retest/schema";
import { parseNmap } from "./nmap.js";
import { parseNuclei } from "./nuclei.js";
import type { ParseResult } from "./raw.js";

export type { ParseResult, RawEvidence, RawFinding } from "./raw.js";
export { nmapFindings, parseNmap, parseNmapXml, portLine } from "./nmap.js";
export type { NmapHost, NmapPort, NmapScan, NmapScript, NmapService, PortState, ScriptValue, ScriptValues } from "./nmap.js";
export { nucleiFindings, parseNuclei, parseNucleiLine } from "./nuclei.js";
export type { NucleiClassification, NucleiResult } from "./nuclei.js";
export { UNASSESSED_IMPACT, UNWRITTEN_FIX, findingId, normalize } from "./normalize.js";
export type { NormalizeOptions, Normalized } from "./normalize.js";

const PARSERS: Partial<Record<Tool, (text: string) => ParseResult>> = {
  nmap: parseNmap,
  nuclei: parseNuclei,
};

/** The tools whose output can be imported so far. */
export const PARSEABLE_TOOLS = Object.keys(PARSERS) as Tool[];

export function canParse(tool: Tool): boolean {
  return tool in PARSERS;
}

/** Parse a scanner's output by tool name. Throws when the tool has no parser yet. */
export function parse(tool: Tool, text: string): ParseResult {
  const parser = PARSERS[tool];
  if (!parser) throw new Error(`no parser for ${tool} yet`);
  return parser(text);
}
