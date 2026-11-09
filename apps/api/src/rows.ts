import type { Assessment, Asset, Evidence, Finding } from "@retest/schema";
import type { AssessmentRow, AssetRow, AuditRow, EvidenceRow, FindingRow, ImportRow } from "./db/schema.js";

/**
 * Rows in, schema objects out, and back. The API speaks the schema package's types on the
 * wire; the tables keep the same data with timestamps as timestamps and a few columns pulled
 * out of the JSON for filtering. These are the only places that know both shapes.
 */

export interface AssessmentOut extends Assessment {
  ownerId: string;
}

export function toAssessment(row: AssessmentRow): AssessmentOut {
  return {
    id: row.id,
    ownerId: row.ownerId,
    name: row.name,
    ...(row.client ? { client: row.client } : {}),
    scope: row.scope,
    phase: row.phase,
    status: row.status,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function toAsset(row: AssetRow): Asset {
  return {
    id: row.id,
    assessmentId: row.assessmentId,
    kind: row.kind,
    name: row.name,
    ...(row.host ? { host: row.host } : {}),
    ...(row.port !== null ? { port: row.port } : {}),
    ...(row.url ? { url: row.url } : {}),
    inScope: row.inScope,
    tags: row.tags,
  };
}

export function fromAsset(asset: Asset): AssetRow {
  return {
    id: asset.id,
    assessmentId: asset.assessmentId,
    kind: asset.kind,
    name: asset.name,
    host: asset.host ?? null,
    port: asset.port ?? null,
    url: asset.url ?? null,
    inScope: asset.inScope,
    tags: asset.tags,
  };
}

export function toEvidence(row: EvidenceRow): Evidence {
  return {
    id: row.id,
    findingId: row.findingId,
    kind: row.kind,
    ...(row.title ? { title: row.title } : {}),
    content: row.content,
    redacted: row.redacted,
    ...(row.capturedAt ? { capturedAt: row.capturedAt.toISOString() } : {}),
    ...(row.source ? { source: row.source } : {}),
  };
}

export function fromEvidence(e: Evidence, findingId: string): EvidenceRow {
  return {
    id: e.id,
    findingId,
    kind: e.kind,
    title: e.title ?? null,
    content: e.content,
    redacted: e.redacted,
    capturedAt: e.capturedAt ? new Date(e.capturedAt) : null,
    source: e.source ?? null,
  };
}

export function toFinding(row: FindingRow, evidence: EvidenceRow[]): Finding {
  return {
    id: row.id,
    assessmentId: row.assessmentId,
    title: row.title,
    assetId: row.assetId,
    scope: row.scope,
    impact: row.impact,
    evidence: evidence.map(toEvidence),
    risk: row.risk,
    fix: row.fix,
    ...(row.retest ? { retest: row.retest } : {}),
    phase: row.phase,
    status: row.status,
    ...(row.falsePositiveReason ? { falsePositiveReason: row.falsePositiveReason } : {}),
    sources: row.sources,
    mappings: row.mappings,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function fromFinding(f: Finding): FindingRow {
  return {
    id: f.id,
    assessmentId: f.assessmentId,
    assetId: f.assetId,
    title: f.title,
    scope: f.scope,
    impact: f.impact,
    risk: f.risk,
    severity: f.risk.severity,
    fix: f.fix,
    retest: f.retest ?? null,
    phase: f.phase,
    status: f.status,
    falsePositiveReason: f.falsePositiveReason ?? null,
    sources: f.sources,
    mappings: f.mappings,
    createdAt: new Date(f.createdAt),
    updatedAt: new Date(f.updatedAt),
  };
}

/** A finding in a list: everything but the evidence, plus how many pieces there are. */
export type FindingSummary = Omit<Finding, "evidence"> & { evidenceCount: number };

export function toFindingSummary(row: FindingRow, evidenceCount: number): FindingSummary {
  const { evidence, ...rest } = toFinding(row, []);
  void evidence;
  return { ...rest, evidenceCount };
}

export interface AuditLine {
  id: number;
  assessmentId: string;
  findingId: string | null;
  actor: string;
  action: AuditRow["action"];
  field: string;
  from: string | null;
  to: string | null;
  reason: string | null;
  at: string;
}

export function toAuditLine(row: AuditRow): AuditLine {
  return {
    id: row.id,
    assessmentId: row.assessmentId,
    findingId: row.findingId,
    actor: row.actor,
    action: row.action,
    field: row.field,
    from: row.fromValue,
    to: row.toValue,
    reason: row.reason,
    at: row.at.toISOString(),
  };
}

export interface ImportOut {
  id: string;
  assessmentId: string;
  actor: string;
  tool: ImportRow["tool"];
  filename: string | null;
  parsed: number;
  created: number;
  merged: number;
  assetsCreated: number;
  warnings: string[];
  at: string;
}

export function toImport(row: ImportRow): ImportOut {
  return { ...row, at: row.at.toISOString() };
}
