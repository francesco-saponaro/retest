import type { AssetKind, EvidenceKind, FindingStatus, Mappings, Phase, Retest, Risk, Scope, Severity, Source, Tool } from "@retest/schema";
import { boolean, foreignKey, index, integer, jsonb, pgTable, primaryKey, serial, text, timestamp } from "drizzle-orm/pg-core";

const when = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

/**
 * The tables. One per thing that has its own life: an assessment is authorised and closed on
 * its own; an asset exists before any finding is made against it and after they are all closed;
 * a finding moves through the phases on its own; a piece of evidence is added, redacted and
 * cited on its own; an audit line is written once and never changed. What a row is made of
 * (a scope, a risk, the list of sources) is kept as JSON in the row, because the schema package
 * already says what is valid there and nothing ever queries inside it except for filters, which
 * get their own column.
 *
 * Every table except `assessments` carries the assessment it belongs to, so that a request can
 * be checked against the owner of the assessment before it touches anything.
 */

export const assessments = pgTable(
  "assessments",
  {
    id: text("id").primaryKey(),
    /** The `sub` of the token that created it. The one field every authorisation check reads. */
    ownerId: text("owner_id").notNull(),
    name: text("name").notNull(),
    client: text("client"),
    scope: jsonb("scope").$type<Scope>().notNull(),
    phase: text("phase").$type<Phase>().notNull(),
    status: text("status").$type<"draft" | "active" | "closed">().notNull(),
    createdAt: when("created_at").notNull(),
    updatedAt: when("updated_at").notNull(),
  },
  (t) => [index("assessments_owner_idx").on(t.ownerId)],
);

export const assets = pgTable(
  "assets",
  {
    /** `asset-host-127-0-0-1`, `asset-web-127-0-0-1-3000`: named by what it is, so the same host in two assessments has the same id in each. The key is the pair. */
    id: text("id").notNull(),
    assessmentId: text("assessment_id")
      .notNull()
      .references(() => assessments.id, { onDelete: "cascade" }),
    kind: text("kind").$type<AssetKind>().notNull(),
    name: text("name").notNull(),
    host: text("host"),
    port: integer("port"),
    url: text("url"),
    inScope: boolean("in_scope").notNull().default(true),
    tags: jsonb("tags").$type<string[]>().notNull().default([]),
  },
  (t) => [primaryKey({ name: "assets_pk", columns: [t.assessmentId, t.id] })],
);

export const findings = pgTable(
  "findings",
  {
    id: text("id").primaryKey(),
    assessmentId: text("assessment_id")
      .notNull()
      .references(() => assessments.id, { onDelete: "cascade" }),
    assetId: text("asset_id").notNull(),
    title: text("title").notNull(),
    scope: text("scope").notNull(),
    impact: text("impact").notNull(),
    risk: jsonb("risk").$type<Risk>().notNull(),
    /** A copy of `risk.severity`, so the table can be filtered and counted without opening the JSON. */
    severity: text("severity").$type<Severity>().notNull(),
    fix: text("fix").notNull(),
    retest: jsonb("retest").$type<Retest>(),
    phase: text("phase").$type<Phase>().notNull(),
    status: text("status").$type<FindingStatus>().notNull(),
    falsePositiveReason: text("false_positive_reason"),
    sources: jsonb("sources").$type<Source[]>().notNull().default([]),
    mappings: jsonb("mappings").$type<Mappings>().notNull(),
    createdAt: when("created_at").notNull(),
    updatedAt: when("updated_at").notNull(),
  },
  (t) => [
    index("findings_assessment_idx").on(t.assessmentId),
    index("findings_asset_idx").on(t.assessmentId, t.assetId),
    index("findings_severity_idx").on(t.assessmentId, t.severity),
    // An asset is keyed by (assessment, id), so a finding can only point at an asset of its own assessment.
    foreignKey({
      name: "findings_asset_in_assessment_fk",
      columns: [t.assetId, t.assessmentId],
      foreignColumns: [assets.id, assets.assessmentId],
    }).onDelete("cascade"),
  ],
);

export const evidence = pgTable(
  "evidence",
  {
    id: text("id").primaryKey(),
    findingId: text("finding_id")
      .notNull()
      .references(() => findings.id, { onDelete: "cascade" }),
    kind: text("kind").$type<EvidenceKind>().notNull(),
    title: text("title"),
    content: text("content").notNull(),
    redacted: boolean("redacted").notNull().default(false),
    capturedAt: when("captured_at"),
    source: jsonb("source").$type<Source>(),
  },
  (t) => [index("evidence_finding_idx").on(t.findingId)],
);

export const AUDIT_ACTIONS = ["phase", "status", "retest", "import"] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export const auditLog = pgTable(
  "audit_log",
  {
    id: serial("id").primaryKey(),
    assessmentId: text("assessment_id")
      .notNull()
      .references(() => assessments.id, { onDelete: "cascade" }),
    findingId: text("finding_id").references(() => findings.id, { onDelete: "cascade" }),
    /** The `sub` of the token that did it. */
    actor: text("actor").notNull(),
    action: text("action").$type<AuditAction>().notNull(),
    field: text("field").notNull(),
    fromValue: text("from_value"),
    toValue: text("to_value"),
    reason: text("reason"),
    at: when("at").notNull(),
  },
  (t) => [index("audit_assessment_idx").on(t.assessmentId, t.id), index("audit_finding_idx").on(t.findingId)],
);

export const imports = pgTable(
  "imports",
  {
    id: text("id").primaryKey(),
    assessmentId: text("assessment_id")
      .notNull()
      .references(() => assessments.id, { onDelete: "cascade" }),
    actor: text("actor").notNull(),
    tool: text("tool").$type<Tool>().notNull(),
    filename: text("filename"),
    /** Raw findings the parser produced, findings created, findings folded into existing ones, assets created. */
    parsed: integer("parsed").notNull(),
    created: integer("created").notNull(),
    merged: integer("merged").notNull(),
    assetsCreated: integer("assets_created").notNull(),
    warnings: jsonb("warnings").$type<string[]>().notNull().default([]),
    at: when("at").notNull(),
  },
  (t) => [index("imports_assessment_idx").on(t.assessmentId)],
);

export type AssessmentRow = typeof assessments.$inferSelect;
export type AssetRow = typeof assets.$inferSelect;
export type FindingRow = typeof findings.$inferSelect;
export type EvidenceRow = typeof evidence.$inferSelect;
export type AuditRow = typeof auditLog.$inferSelect;
export type ImportRow = typeof imports.$inferSelect;
