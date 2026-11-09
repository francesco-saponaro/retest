import { and, asc, eq } from "drizzle-orm";
import { auditLog, type AuditAction, type Db } from "../db/index.js";
import { toAuditLine, type AuditLine } from "../rows.js";

export interface AuditEntry {
  assessmentId: string;
  findingId?: string;
  actor: string;
  action: AuditAction;
  field: string;
  from?: string | null;
  to?: string | null;
  reason?: string;
  at: Date;
}

/** One line, written once. Nothing in the API updates or deletes an audit line. */
export async function record(db: Db, entry: AuditEntry): Promise<void> {
  await db.insert(auditLog).values({
    assessmentId: entry.assessmentId,
    findingId: entry.findingId ?? null,
    actor: entry.actor,
    action: entry.action,
    field: entry.field,
    fromValue: entry.from ?? null,
    toValue: entry.to ?? null,
    reason: entry.reason ?? null,
    at: entry.at,
  });
}

/** The lines of an assessment, oldest first; of one finding when `findingId` is given. */
export async function listAudit(db: Db, assessmentId: string, findingId?: string): Promise<AuditLine[]> {
  const rows = await db
    .select()
    .from(auditLog)
    .where(and(eq(auditLog.assessmentId, assessmentId), findingId ? eq(auditLog.findingId, findingId) : undefined))
    .orderBy(asc(auditLog.id));
  return rows.map(toAuditLine);
}
