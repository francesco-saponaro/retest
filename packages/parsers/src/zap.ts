import type { Severity } from "@retest/schema";
import { z } from "zod";
import type { ParseResult, RawEvidence, RawFinding } from "./raw.js";
import { stripHtml } from "./text.js";

/**
 * OWASP ZAP's traditional JSON report (`zap-baseline.py -J`, or Report > Generate > JSON in the
 * desktop app). ZAP is a proxy and a scanner: it crawls a site, sends its passive and active
 * checks, and reports one alert per check that fired, with every URL where it fired listed as an
 * instance. The report groups alerts under the site they belong to.
 */

const str = z.union([z.string(), z.number()]).transform((v) => String(v));

const InstanceSchema = z
  .object({
    uri: z.string().min(1),
    method: z.string().optional(),
    param: z.string().optional(),
    attack: z.string().optional(),
    evidence: z.string().optional(),
    otherinfo: z.string().optional(),
  })
  .loose();

const AlertSchema = z
  .object({
    pluginid: str,
    alertRef: str.optional(),
    alert: z.string().min(1),
    name: z.string().optional(),
    riskcode: str,
    confidence: str,
    riskdesc: z.string().optional(),
    desc: z.string().optional(),
    instances: z.array(InstanceSchema).default([]),
    count: str.optional(),
    solution: z.string().optional(),
    otherinfo: z.string().optional(),
    reference: z.string().optional(),
    cweid: str.optional(),
    wascid: str.optional(),
    sourceid: str.optional(),
  })
  .loose();

const SiteSchema = z
  .object({
    "@name": z.string().min(1),
    "@host": z.string().min(1),
    "@port": str,
    "@ssl": z.union([z.string(), z.boolean()]).optional(),
    alerts: z.array(AlertSchema).default([]),
  })
  .loose();

const ReportSchema = z
  .object({
    "@programName": z.literal("ZAP"),
    "@version": z.string().optional(),
    "@generated": z.string().optional(),
    site: z.array(SiteSchema),
  })
  .loose();

export type ZapConfidence = "false-positive" | "low" | "medium" | "high" | "confirmed";

export interface ZapInstance {
  uri: string;
  method: string;
  param: string;
  attack: string;
  evidence: string;
  otherInfo: string;
}

export interface ZapAlert {
  pluginId: string;
  alertRef: string;
  name: string;
  /** ZAP's risk, 0 to 3, as a severity word. */
  risk: Severity;
  /** How sure ZAP is that the alert is real. A passive rule that matched a pattern is usually low or medium. */
  confidence: ZapConfidence;
  description: string;
  solution: string;
  otherInfo: string;
  references: string[];
  cweId?: number;
  wascId?: number;
  count: number;
  instances: ZapInstance[];
}

export interface ZapSite {
  name: string;
  host: string;
  port: number;
  ssl: boolean;
  alerts: ZapAlert[];
}

export interface ZapReport {
  programName: string;
  version?: string;
  generated?: string;
  /** `generated` as ISO 8601, when it could be read. ZAP writes no time zone, so it is taken as UTC. */
  generatedAt?: string;
  sites: ZapSite[];
}

const RISKS: Record<string, Severity> = { "0": "info", "1": "low", "2": "medium", "3": "high" };
const CONFIDENCES: Record<string, ZapConfidence> = { "0": "false-positive", "1": "low", "2": "medium", "3": "high", "4": "confirmed" };

/** Parse the report into its structure. Throws when the text is not a ZAP JSON report. */
export function parseZapReport(text: string): ZapReport {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error("not JSON");
  }
  const parsed = ReportSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`not a ZAP JSON report${issue ? ` (${issue.path.join(".") || "root"}: ${issue.message})` : ""}`);
  }
  const r = parsed.data;
  const report: ZapReport = {
    programName: r["@programName"],
    sites: r.site.map((s) => ({
      name: s["@name"],
      host: s["@host"],
      port: Number(s["@port"]),
      ssl: s["@ssl"] === true || s["@ssl"] === "true",
      alerts: s.alerts.map(toAlert),
    })),
  };
  if (r["@version"]) report.version = r["@version"];
  if (r["@generated"]) {
    report.generated = r["@generated"];
    const at = generatedAt(r["@generated"]);
    if (at) report.generatedAt = at;
  }
  return report;
}

function toAlert(a: z.infer<typeof AlertSchema>): ZapAlert {
  const alert: ZapAlert = {
    pluginId: a.pluginid,
    alertRef: a.alertRef ?? a.pluginid,
    name: a.alert,
    risk: RISKS[a.riskcode] ?? "info",
    confidence: CONFIDENCES[a.confidence] ?? "low",
    description: stripHtml(a.desc ?? ""),
    solution: stripHtml(a.solution ?? ""),
    otherInfo: stripHtml(a.otherinfo ?? ""),
    references: stripHtml(a.reference ?? "")
      .split("\n")
      .filter((line) => /^https?:\/\//.test(line)),
    count: a.count !== undefined ? Number(a.count) : a.instances.length,
    instances: a.instances.map((i) => ({
      uri: i.uri,
      method: i.method ?? "GET",
      param: i.param ?? "",
      attack: i.attack ?? "",
      evidence: i.evidence ?? "",
      otherInfo: i.otherinfo ?? "",
    })),
  };
  const cwe = positiveInt(a.cweid);
  if (cwe !== undefined) alert.cweId = cwe;
  const wasc = positiveInt(a.wascid);
  if (wasc !== undefined) alert.wascId = wasc;
  return alert;
}

function positiveInt(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

const MONTHS: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

/** "Sun, 8 Nov 2026 18:41:07" to ISO 8601. ZAP writes the machine's local time with no zone; it is read as UTC. */
function generatedAt(value: string): string | undefined {
  const m = /^(?:[A-Za-z]{3},\s*)?(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})$/.exec(value.trim());
  if (!m) return undefined;
  const month = MONTHS[m[2]!.toLowerCase()];
  if (month === undefined) return undefined;
  const date = new Date(Date.UTC(Number(m[3]), month, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6])));
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

const SCOPE_INSTANCES = 3;

function pathOf(uri: string): string {
  try {
    const u = new URL(uri);
    return `${u.pathname}${u.search}`;
  } catch {
    return uri;
  }
}

/** `GET /, GET /ftp, GET /robots.txt`, or the first three and a count. */
function scopeOf(alert: ZapAlert): string {
  const places = [...new Set(alert.instances.map((i) => `${i.method} ${pathOf(i.uri)}`))];
  const shown = places.slice(0, SCOPE_INSTANCES).join(", ");
  const rest = places.length - SCOPE_INSTANCES;
  return rest > 0 ? `${shown} and ${rest} more` : shown;
}

function instancesEvidence(alert: ZapAlert): RawEvidence {
  const lines: string[] = [];
  for (const i of alert.instances) {
    lines.push(`${i.method} ${i.uri}`);
    if (i.param) lines.push(`  param: ${i.param}`);
    if (i.attack) lines.push(`  attack: ${i.attack}`);
    if (i.evidence) lines.push(`  evidence: ${i.evidence}`);
    if (i.otherInfo && i.otherInfo !== alert.otherInfo) lines.push(`  note: ${i.otherInfo}`);
  }
  const n = alert.instances.length;
  return { kind: "scanner-output", title: `${n} instance${n === 1 ? "" : "s"} reported by ZAP`, content: lines.join("\n") };
}

/**
 * One raw finding per alert. The instances are the evidence and the scope, not separate
 * findings: ZAP has already decided they are the same problem. ZAP's risk is kept as the
 * severity, its solution as the fix and its CWE as the weakness; its confidence goes in a tag,
 * because a passive pattern match at low confidence is a hint, not a result.
 */
export function zapFindings(report: ZapReport): RawFinding[] {
  const out: RawFinding[] = [];
  for (const site of report.sites) {
    for (const alert of site.alerts) {
      if (alert.instances.length === 0) continue;
      const finding: RawFinding = {
        tool: "zap",
        rawId: alert.pluginId,
        title: alert.name,
        severity: alert.risk,
        host: site.host,
        port: site.port,
        protocol: "tcp",
        url: site.name,
        scope: scopeOf(alert),
        cwe: alert.cweId !== undefined ? [alert.cweId] : [],
        cve: [],
        references: [`https://www.zaproxy.org/docs/alerts/${alert.pluginId}/`, ...alert.references],
        evidence: [instancesEvidence(alert)],
        tags: [`zap-confidence:${alert.confidence}`, ...(alert.wascId !== undefined ? [`wasc-${alert.wascId}`] : [])],
        phase: "assessment",
      };
      const description = [alert.description, alert.otherInfo].filter((t) => t.length > 0).join("\n");
      if (description) finding.description = description;
      if (alert.solution) finding.fix = alert.solution;
      if (report.generatedAt) finding.detectedAt = report.generatedAt;
      out.push(finding);
    }
  }
  return out;
}

/** Parse a whole report. Sites without alerts and alerts without instances are reported as warnings and skipped. */
export function parseZap(text: string): ParseResult & { report: ZapReport } {
  const report = parseZapReport(text);
  const warnings: string[] = [];
  for (const site of report.sites) {
    for (const alert of site.alerts) {
      if (alert.instances.length === 0) warnings.push(`alert ${alert.pluginId} (${alert.name}) has no instances; skipped`);
    }
    if (site.alerts.length === 0) warnings.push(`site ${site.name} has no alerts`);
  }
  return { tool: "zap", report, findings: zapFindings(report), warnings };
}
