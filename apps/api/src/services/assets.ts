import { AssetKindSchema, AssetSchema, PortSchema, type Asset } from "@retest/schema";
import { and, asc, count, eq } from "drizzle-orm";
import { z } from "zod";
import type { Principal } from "../auth.js";
import { assets, findings, type AssessmentRow, type AssetRow, type Db } from "../db/index.js";
import { HttpError, invalid, newId } from "../http.js";
import { fromAsset, toAsset } from "../rows.js";
import { loadAssessment } from "./assessments.js";

/** What a client may send. The id and the assessment come from the server and the path. */
export const NewAssetSchema = z.strictObject({
  kind: AssetKindSchema,
  name: z.string().min(1).max(200),
  host: z.string().min(1).optional(),
  port: PortSchema.optional(),
  url: z.url().optional(),
  inScope: z.boolean().optional(),
  tags: z.array(z.string().min(1)).optional(),
});

export const AssetPatchSchema = z.strictObject({
  kind: AssetKindSchema.optional(),
  name: z.string().min(1).max(200).optional(),
  host: z.string().min(1).nullable().optional(),
  port: PortSchema.nullable().optional(),
  url: z.url().nullable().optional(),
  inScope: z.boolean().optional(),
  tags: z.array(z.string().min(1)).optional(),
});

/** An asset of an assessment the caller may see, or a 404. The assessment is checked first; the asset is looked up by the pair. */
export async function requireAsset(db: Db, assessmentId: string, id: string, who: Principal): Promise<{ asset: AssetRow; assessment: AssessmentRow }> {
  const assessment = await loadAssessment(db, assessmentId, who);
  const [asset] = assessment ? await db.select().from(assets).where(and(eq(assets.assessmentId, assessment.id), eq(assets.id, id))).limit(1) : [];
  if (!assessment || !asset) throw new HttpError(404, "asset not found");
  return { asset, assessment };
}

export async function createAsset(db: Db, assessmentId: string, input: z.infer<typeof NewAssetSchema>): Promise<Asset> {
  const parsed = AssetSchema.safeParse({ ...input, id: newId("asset"), assessmentId });
  if (!parsed.success) invalid("body", parsed.error);
  await db.insert(assets).values(fromAsset(parsed.data));
  return parsed.data;
}

export async function listAssets(db: Db, assessmentId: string): Promise<Asset[]> {
  const rows = await db.select().from(assets).where(eq(assets.assessmentId, assessmentId)).orderBy(asc(assets.name), asc(assets.id));
  return rows.map(toAsset);
}

export async function findingCount(db: Db, assessmentId: string, assetId: string): Promise<number> {
  const [row] = await db.select({ n: count() }).from(findings).where(and(eq(findings.assessmentId, assessmentId), eq(findings.assetId, assetId)));
  return row?.n ?? 0;
}

/** Apply a patch and run the whole asset through the schema again, so its rules hold after the change too. */
export async function updateAsset(db: Db, row: AssetRow, patch: z.infer<typeof AssetPatchSchema>): Promise<Asset> {
  const current = toAsset(row);
  const next: Record<string, unknown> = { ...current };
  for (const [k, v] of Object.entries(patch)) {
    if (v === null) delete next[k];
    else if (v !== undefined) next[k] = v;
  }
  const parsed = AssetSchema.safeParse(next);
  if (!parsed.success) invalid("body", parsed.error);
  await db.update(assets).set(fromAsset(parsed.data)).where(and(eq(assets.assessmentId, row.assessmentId), eq(assets.id, row.id)));
  return parsed.data;
}
