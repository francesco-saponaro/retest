import type { Severity } from "@retest/schema";
import { z } from "zod";
import type { ParseResult, RawFinding } from "./raw.js";

/**
 * Prowler's OCSF output (`prowler aws -M json-ocsf`): one Detection Finding per check per
 * resource, in the Open Cybersecurity Schema Framework shape. Prowler reads an account's
 * configuration through the cloud API and compares it with its checks; a result is a setting
 * as it was at scan time. Every check is reported, whether it passed or failed, so the failed
 * ones are the candidates and the passed ones are the coverage.
 */

const StrSchema = z.string();

const ResultSchema = z
  .object({
    message: z.string().optional(),
    metadata: z
      .object({
        event_code: z.string().min(1),
        product: z.object({ name: z.literal("Prowler"), version: z.string().optional() }).loose(),
      })
      .loose(),
    severity: z.string().optional(),
    severity_id: z.number().optional(),
    status_code: z.string().min(1),
    status_detail: z.string().optional(),
    unmapped: z
      .object({
        related_url: z.string().optional(),
        categories: z.array(z.string()).optional(),
        compliance: z.record(z.string(), z.array(z.string())).optional(),
        notes: z.string().optional(),
      })
      .loose()
      .optional(),
    finding_info: z
      .object({
        uid: z.string().optional(),
        title: z.string().optional(),
        desc: z.string().optional(),
        types: z.array(z.string()).optional(),
      })
      .loose()
      .optional(),
    resources: z
      .array(
        z
          .object({
            uid: StrSchema.optional(),
            name: StrSchema.optional(),
            type: StrSchema.optional(),
            region: StrSchema.optional(),
            group: z.object({ name: z.string().optional() }).loose().optional(),
          })
          .loose(),
      )
      .optional(),
    cloud: z
      .object({
        provider: z.string().optional(),
        region: z.string().optional(),
        account: z.object({ uid: z.string().optional(), name: z.string().optional() }).loose().optional(),
      })
      .loose()
      .optional(),
    remediation: z.object({ desc: z.string().optional(), references: z.array(z.string()).optional() }).loose().optional(),
    risk_details: z.string().optional(),
    time: z.number().optional(),
    time_dt: z.string().optional(),
  })
  .loose();

const OutputSchema = z.array(ResultSchema).min(1);

export type ProwlerStatus = "FAIL" | "PASS" | "MANUAL" | string;

export interface ProwlerCheck {
  checkId: string;
  uid?: string;
  title: string;
  description: string;
  severity: Severity;
  status: ProwlerStatus;
  statusDetail: string;
  provider: string;
  account: { uid: string; name?: string };
  region?: string;
  resource?: { uid: string; name?: string; type?: string; group?: string };
  risk: string;
  remediation: string;
  /** Links from the remediation. The commands that Prowler lists next to them are kept in `commands`. */
  references: string[];
  commands: string[];
  relatedUrl?: string;
  categories: string[];
  compliance: Record<string, string[]>;
  types: string[];
  /** OCSF `time_dt`, as Prowler wrote it (no zone). */
  time?: string;
  /** OCSF `time`, epoch seconds, as ISO 8601 UTC. */
  timeAt?: string;
  product: { name: string; version?: string };
}

const SEVERITY_WORDS: Record<string, Severity> = {
  informational: "info",
  info: "info",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

const SEVERITY_IDS: Record<number, Severity> = { 1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical" };

function toSeverity(word: string | undefined, id: number | undefined): Severity {
  const fromWord = word ? SEVERITY_WORDS[word.toLowerCase()] : undefined;
  if (fromWord) return fromWord;
  return (id !== undefined ? SEVERITY_IDS[id] : undefined) ?? "info";
}

function isUrl(value: string): boolean {
  return /^https?:\/\//i.test(value.trim());
}

function toCheck(r: z.infer<typeof ResultSchema>): ProwlerCheck {
  const refs = r.remediation?.references ?? [];
  const resource = r.resources?.[0];
  const check: ProwlerCheck = {
    checkId: r.metadata.event_code,
    title: (r.finding_info?.title ?? r.metadata.event_code).trim(),
    description: (r.finding_info?.desc ?? "").trim(),
    severity: toSeverity(r.severity, r.severity_id),
    status: r.status_code,
    statusDetail: (r.status_detail ?? r.message ?? "").trim(),
    provider: r.cloud?.provider ?? "cloud",
    account: { uid: r.cloud?.account?.uid ?? "unknown-account" },
    risk: (r.risk_details ?? "").trim(),
    remediation: (r.remediation?.desc ?? "").trim(),
    references: refs.filter(isUrl),
    commands: refs.filter((x) => !isUrl(x)),
    categories: r.unmapped?.categories ?? [],
    compliance: r.unmapped?.compliance ?? {},
    types: r.finding_info?.types ?? [],
    product: { name: r.metadata.product.name },
  };
  if (r.finding_info?.uid) check.uid = r.finding_info.uid;
  if (r.cloud?.account?.name) check.account.name = r.cloud.account.name;
  const region = resource?.region ?? r.cloud?.region;
  if (region) check.region = region;
  if (resource?.uid) {
    check.resource = { uid: resource.uid };
    if (resource.name) check.resource.name = resource.name;
    if (resource.type) check.resource.type = resource.type;
    if (resource.group?.name) check.resource.group = resource.group.name;
  }
  if (r.unmapped?.related_url) check.relatedUrl = r.unmapped.related_url;
  if (r.time_dt) check.time = r.time_dt;
  if (r.time !== undefined && Number.isFinite(r.time)) check.timeAt = new Date(r.time * 1000).toISOString();
  if (r.metadata.product.version) check.product.version = r.metadata.product.version;
  return check;
}

/** Parse the OCSF array into checks. Throws when the text is not Prowler's OCSF output. */
export function parseProwlerOcsf(text: string): ProwlerCheck[] {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error("not JSON");
  }
  const parsed = OutputSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`not Prowler OCSF output${issue ? ` (${issue.path.join(".") || "root"}: ${issue.message})` : ""}`);
  }
  return parsed.data.map(toCheck);
}

/** `CIS-3.0` beats `CIS-2.0`: the newest CIS benchmark version a check is mapped to, as a tag. */
function cisTag(compliance: Record<string, string[]>): string | undefined {
  const versions = Object.keys(compliance)
    .map((k) => /^CIS-(\d+(?:\.\d+)?)$/.exec(k))
    .filter((m): m is RegExpExecArray => m !== null)
    .sort((a, b) => Number(b[1]) - Number(a[1]));
  const best = versions[0];
  if (!best) return undefined;
  const ids = compliance[best[0]] ?? [];
  return ids.length > 0 ? `cis-${best[1]}:${ids.join(",")}` : undefined;
}

function evidenceFor(c: ProwlerCheck): string {
  const lines = [`status: ${c.status}`];
  if (c.statusDetail) lines.push(`detail: ${c.statusDetail}`);
  if (c.resource) lines.push(`resource: ${c.resource.uid}${c.resource.type ? ` (${c.resource.type})` : ""}`);
  if (c.region) lines.push(`region: ${c.region}`);
  lines.push(`account: ${c.account.uid}${c.account.name ? ` (${c.account.name})` : ""}`);
  return lines.join("\n");
}

/**
 * One raw finding per failed check, on the cloud account, with the resource as the scope. The
 * status detail is the title because it names the resource and the setting; the check's title
 * and its risk text are the description. Prowler gives no CWE: what a cloud misconfiguration is
 * in CWE terms is for `classify()` to say.
 */
export function prowlerFindings(checks: ProwlerCheck[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (const c of checks) {
    if (c.status !== "FAIL") continue;
    const cloud: NonNullable<RawFinding["cloud"]> = { provider: c.provider, account: c.account.uid };
    if (c.account.name) cloud.accountName = c.account.name;
    if (c.region) cloud.region = c.region;
    if (c.resource) {
      cloud.resource = c.resource.uid;
      if (c.resource.type) cloud.resourceType = c.resource.type;
    }
    const references = [...c.references];
    if (c.relatedUrl && !references.includes(c.relatedUrl)) references.push(c.relatedUrl);
    const cis = cisTag(c.compliance);
    const finding: RawFinding = {
      tool: "prowler",
      rawId: c.checkId,
      title: c.statusDetail || c.title,
      severity: c.severity,
      cloud,
      scope: c.resource?.uid ?? c.account.uid,
      cwe: [],
      cve: [],
      references,
      evidence: [{ kind: "scanner-output", title: `${c.checkId}${c.resource?.name ? ` on ${c.resource.name}` : ""}`, content: evidenceFor(c) }],
      tags: [c.provider, ...(c.resource?.group ? [c.resource.group] : []), ...(c.resource?.type ? [c.resource.type] : []), ...c.categories, ...(cis ? [cis] : [])],
      phase: "assessment",
    };
    const description = [c.title, c.risk].filter((t) => t.length > 0).join("\n");
    if (description) finding.description = description;
    const fix = [c.remediation, ...c.commands].filter((t) => t.length > 0).join("\n");
    if (fix) finding.fix = fix;
    if (c.timeAt) finding.detectedAt = c.timeAt;
    out.push(finding);
  }
  return out;
}

/** Parse a whole file. Passed checks are counted, not reported; manual checks are listed as a warning so nobody forgets them. */
export function parseProwler(text: string): ParseResult & { checks: ProwlerCheck[]; passed: number; manual: number } {
  const checks = parseProwlerOcsf(text);
  const passed = checks.filter((c) => c.status === "PASS").length;
  const manualChecks = checks.filter((c) => c.status === "MANUAL");
  const warnings: string[] = [];
  if (manualChecks.length > 0) {
    const ids = [...new Set(manualChecks.map((c) => c.checkId))];
    warnings.push(`${ids.length} check${ids.length === 1 ? "" : "s"} need${ids.length === 1 ? "s" : ""} a manual look: ${ids.join(", ")}`);
  }
  return { tool: "prowler", checks, passed, manual: manualChecks.length, findings: prowlerFindings(checks), warnings };
}
