import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import type { RouteContext } from "../app.js";
import { validate } from "../http.js";
import { requireAssessment } from "../services/assessments.js";
import { AssetPatchSchema, NewAssetSchema, createAsset, findingCount, listAssets, requireAsset, updateAsset } from "../services/assets.js";
import { toAsset } from "../rows.js";
import { IdParams } from "./assessments.js";

const AssetParams = z.object({ id: z.string().min(1).max(100), assetId: z.string().min(1).max(100) });

export const assetRoutes: FastifyPluginAsync<RouteContext> = async (app, { db }) => {
  app.post("/assessments/:id/assets", async (req, reply) => {
    const { id } = validate(IdParams, req.params, "params");
    const input = validate(NewAssetSchema, req.body, "body");
    const assessment = await requireAssessment(db, id, req.principal);
    return reply.code(201).send(await createAsset(db, assessment.id, input));
  });

  app.get("/assessments/:id/assets", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const assessment = await requireAssessment(db, id, req.principal);
    return { items: await listAssets(db, assessment.id) };
  });

  // An asset is keyed by (assessment, id): the same host in two assessments is two rows with the same id.
  app.get("/assessments/:id/assets/:assetId", async (req) => {
    const { id, assetId } = validate(AssetParams, req.params, "params");
    const { asset } = await requireAsset(db, id, assetId, req.principal);
    return { ...toAsset(asset), findingCount: await findingCount(db, asset.assessmentId, asset.id) };
  });

  app.patch("/assessments/:id/assets/:assetId", async (req) => {
    const { id, assetId } = validate(AssetParams, req.params, "params");
    const patch = validate(AssetPatchSchema, req.body, "body");
    const { asset } = await requireAsset(db, id, assetId, req.principal);
    return updateAsset(db, asset, patch);
  });
};
