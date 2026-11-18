import { SEVERITIES, type Severity } from "@retest/schema";
import { z } from "zod";
import type { ParseResult, RawFinding } from "./raw.js";

/**
 * Trivy's JSON output (`trivy image -f json`, also `trivy fs` and `trivy repo`). Trivy reads the
 * packages installed in an image or a directory and looks each version up in the vulnerability
 * databases it mirrors (the distribution's security tracker, GitHub's advisories, NVD). A row is
 * a version match: this package at this version is listed against this CVE. Whether the
 * vulnerable code is used, or reachable, the report cannot say.
 */

const CvssEntrySchema = z
  .object({
    V2Vector: z.string().optional(),
    V3Vector: z.string().optional(),
    V2Score: z.number().optional(),
    V3Score: z.number().optional(),
  })
  .loose();

const VulnerabilitySchema = z
  .object({
    VulnerabilityID: z.string().min(1),
    PkgID: z.string().optional(),
    PkgName: z.string().min(1),
    PkgPath: z.string().optional(),
    InstalledVersion: z.string().min(1),
    FixedVersion: z.string().optional(),
    Status: z.string().optional(),
    SeveritySource: z.string().optional(),
    PrimaryURL: z.string().optional(),
    DataSource: z.object({ ID: z.string().optional(), Name: z.string().optional(), URL: z.string().optional() }).loose().optional(),
    Title: z.string().optional(),
    Description: z.string().optional(),
    Severity: z.string().optional(),
    CweIDs: z.array(z.string()).optional(),
    CVSS: z.record(z.string(), CvssEntrySchema).optional(),
    References: z.array(z.string()).optional(),
    PublishedDate: z.string().optional(),
    LastModifiedDate: z.string().optional(),
  })
  .loose();

const ResultSchema = z
  .object({
    Target: z.string().min(1),
    Class: z.string().optional(),
    Type: z.string().optional(),
    Vulnerabilities: z.array(VulnerabilitySchema).optional(),
  })
  .loose();

const ReportSchema = z
  .object({
    SchemaVersion: z.literal(2),
    CreatedAt: z.string().optional(),
    ArtifactName: z.string().min(1),
    ArtifactType: z.string().optional(),
    Metadata: z
      .object({
        OS: z.object({ Family: z.string().optional(), Name: z.string().optional() }).loose().optional(),
        RepoTags: z.array(z.string()).optional(),
      })
      .loose()
      .optional(),
    Results: z.array(ResultSchema).default([]),
  })
  .loose();

export interface TrivyCvss {
  /** Which database the vector came from: `nvd`, `ghsa`, `redhat`, ... */
  source: string;
  vector: string;
  score?: number;
}

export interface TrivyVulnerability {
  id: string;
  pkgName: string;
  pkgId: string;
  pkgPath?: string;
  installedVersion: string;
  fixedVersion?: string;
  status?: string;
  /** Trivy's severity word, lower-cased; UNKNOWN becomes info. */
  severity: Severity;
  severitySource?: string;
  title?: string;
  description: string;
  cwe: number[];
  /** The CVSS v3 vector Trivy carries, NVD's first, when any source has one. */
  cvss?: TrivyCvss;
  primaryUrl?: string;
  dataSource?: { id?: string; name?: string; url?: string };
  references: string[];
  publishedAt?: string;
  lastModifiedAt?: string;
}

export interface TrivyResult {
  target: string;
  class?: string;
  type?: string;
  vulnerabilities: TrivyVulnerability[];
}

export interface TrivyReport {
  schemaVersion: number;
  createdAt?: string;
  artifactName: string;
  artifactType?: string;
  os?: { family?: string; name?: string };
  results: TrivyResult[];
}

function toSeverity(value: string | undefined): Severity {
  const v = (value ?? "").toLowerCase();
  return (SEVERITIES as readonly string[]).includes(v) ? (v as Severity) : "info";
}

function cweNumbers(ids: string[] | undefined): number[] {
  return [...new Set((ids ?? []).map((id) => Number(id.replace(/^CWE-/i, ""))).filter((n) => Number.isInteger(n) && n > 0))];
}

function pickCvss(entries: Record<string, z.infer<typeof CvssEntrySchema>> | undefined): TrivyCvss | undefined {
  if (!entries) return undefined;
  const order = ["nvd", ...Object.keys(entries).filter((k) => k !== "nvd")];
  for (const source of order) {
    const e = entries[source];
    if (e?.V3Vector) {
      const cvss: TrivyCvss = { source, vector: e.V3Vector };
      if (e.V3Score !== undefined) cvss.score = e.V3Score;
      return cvss;
    }
  }
  return undefined;
}

function toVulnerability(v: z.infer<typeof VulnerabilitySchema>): TrivyVulnerability {
  const vuln: TrivyVulnerability = {
    id: v.VulnerabilityID,
    pkgName: v.PkgName,
    pkgId: v.PkgID ?? `${v.PkgName}@${v.InstalledVersion}`,
    installedVersion: v.InstalledVersion,
    severity: toSeverity(v.Severity),
    description: (v.Description ?? "").trim(),
    cwe: cweNumbers(v.CweIDs),
    references: v.References ?? [],
  };
  if (v.PkgPath) vuln.pkgPath = v.PkgPath;
  if (v.FixedVersion) vuln.fixedVersion = v.FixedVersion;
  if (v.Status) vuln.status = v.Status;
  if (v.SeveritySource) vuln.severitySource = v.SeveritySource;
  if (v.Title) vuln.title = v.Title;
  const cvss = pickCvss(v.CVSS);
  if (cvss) vuln.cvss = cvss;
  if (v.PrimaryURL) vuln.primaryUrl = v.PrimaryURL;
  if (v.DataSource) {
    const ds: NonNullable<TrivyVulnerability["dataSource"]> = {};
    if (v.DataSource.ID) ds.id = v.DataSource.ID;
    if (v.DataSource.Name) ds.name = v.DataSource.Name;
    if (v.DataSource.URL) ds.url = v.DataSource.URL;
    vuln.dataSource = ds;
  }
  if (v.PublishedDate) vuln.publishedAt = v.PublishedDate;
  if (v.LastModifiedDate) vuln.lastModifiedAt = v.LastModifiedDate;
  return vuln;
}

/** Parse the report into its structure. Throws when the text is not a Trivy schema-2 JSON report. */
export function parseTrivyReport(text: string): TrivyReport {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error("not JSON");
  }
  const parsed = ReportSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`not a Trivy JSON report${issue ? ` (${issue.path.join(".") || "root"}: ${issue.message})` : ""}`);
  }
  const r = parsed.data;
  const report: TrivyReport = {
    schemaVersion: r.SchemaVersion,
    // Scanning a saved image (`trivy image --input juice-shop.tar`) names the file, not the image; the tag is in the metadata.
    artifactName: /\.tar(\.gz)?$/.test(r.ArtifactName) && r.Metadata?.RepoTags?.[0] ? r.Metadata.RepoTags[0] : r.ArtifactName,
    results: r.Results.map((res) => {
      const result: TrivyResult = { target: res.Target, vulnerabilities: (res.Vulnerabilities ?? []).map(toVulnerability) };
      if (res.Class) result.class = res.Class;
      if (res.Type) result.type = res.Type;
      return result;
    }),
  };
  if (r.CreatedAt) report.createdAt = r.CreatedAt;
  if (r.ArtifactType) report.artifactType = r.ArtifactType;
  if (r.Metadata?.OS) {
    const os: NonNullable<TrivyReport["os"]> = {};
    if (r.Metadata.OS.Family) os.family = r.Metadata.OS.Family;
    if (r.Metadata.OS.Name) os.name = r.Metadata.OS.Name;
    report.os = os;
  }
  return report;
}

function fixFor(v: TrivyVulnerability): string {
  if (v.fixedVersion) return `Upgrade ${v.pkgName} from ${v.installedVersion} to ${v.fixedVersion} or later.`;
  return `No fixed version of ${v.pkgName} is available yet; track the advisory and consider replacing the package.`;
}

function evidenceFor(result: TrivyResult, v: TrivyVulnerability): string {
  const lines = [`package: ${v.pkgName}`, `installed: ${v.installedVersion}`];
  if (v.fixedVersion) lines.push(`fixed in: ${v.fixedVersion}`);
  if (v.status) lines.push(`status: ${v.status}`);
  if (v.pkgPath) lines.push(`path: ${v.pkgPath}`);
  if (v.dataSource?.name) lines.push(`source: ${v.dataSource.name}${v.dataSource.id ? ` (${v.dataSource.id})` : ""}`);
  lines.push(`severity: ${v.severity.toUpperCase()}${v.severitySource ? ` from ${v.severitySource}` : ""}`);
  return lines.join("\n");
}

/**
 * One raw finding per vulnerability row, on the image (or the directory) that was scanned. The
 * CVE is the finding; the package and version are the scope; the fixed version is the fix, which
 * is the one field a dependency scanner can fill truthfully.
 */
export function trivyFindings(report: TrivyReport): RawFinding[] {
  const out: RawFinding[] = [];
  for (const result of report.results) {
    for (const v of result.vulnerabilities) {
      const finding: RawFinding = {
        tool: "trivy",
        rawId: `${v.id}@${v.pkgName}`,
        title: `${v.id} in ${v.pkgName} ${v.installedVersion}${v.title ? `: ${v.title}` : ""}`,
        severity: v.severity,
        image: report.artifactName,
        scope: `${v.pkgName}@${v.installedVersion}`,
        cwe: v.cwe,
        cve: /^CVE-\d{4}-\d+$/i.test(v.id) ? [v.id.toUpperCase()] : [],
        references: [...(v.primaryUrl ? [v.primaryUrl] : []), ...v.references.filter((r) => r !== v.primaryUrl)],
        evidence: [{ kind: "scanner-output", title: `${result.target}: ${v.pkgId}`, content: evidenceFor(result, v) }],
        tags: [...(result.class ? [result.class] : []), ...(result.type ? [result.type] : []), ...(v.status ? [`trivy-status:${v.status}`] : [])],
        fix: fixFor(v),
        phase: "assessment",
      };
      if (v.description) finding.description = v.description;
      if (v.cvss) {
        finding.cvss = { vector: v.cvss.vector, ...(v.cvss.score !== undefined ? { score: v.cvss.score } : {}) };
      }
      if (report.createdAt) finding.detectedAt = report.createdAt;
      out.push(finding);
    }
  }
  return out;
}

/** Parse a whole report. A row with no CVSS v3 vector is reported: its severity cannot be checked against anything. */
export interface TrivyOptions {
  /** The image's name, when the report only names a saved copy of it (`juice-shop.tar`). */
  image?: string;
}

export function parseTrivy(text: string, options: TrivyOptions = {}): ParseResult & { report: TrivyReport } {
  const report = parseTrivyReport(text);
  if (options.image) report.artifactName = options.image;
  const warnings: string[] = [];
  for (const result of report.results) {
    for (const v of result.vulnerabilities) {
      if (!v.cvss) warnings.push(`${v.id} in ${v.pkgName} has no CVSS v3 vector; its severity is Trivy's word only`);
    }
  }
  return { tool: "trivy", report, findings: trivyFindings(report), warnings };
}
