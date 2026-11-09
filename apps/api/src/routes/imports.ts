import rateLimit from "@fastify/rate-limit";
import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { IMPORT_BODY_LIMIT, type RouteContext } from "../app.js";
import { HttpError, validate } from "../http.js";
import { requireAssessment } from "../services/assessments.js";
import { ImportBodySchema, ImportQuerySchema, listImports, runImport } from "../services/imports.js";
import { IdParams } from "./assessments.js";

export interface ImportRouteOptions extends RouteContext {
  rateLimit: { max: number; timeWindow: string | number; keyGenerator: (req: FastifyRequest) => Promise<string> };
}

export const importRoutes: FastifyPluginAsync<ImportRouteOptions> = async (app, { db, now, rateLimit: limit }) => {
  // Imports parse whole files, so the upload route gets a second, tighter limit of its own.
  await app.register(rateLimit, { global: false, keyGenerator: limit.keyGenerator });

  // A scanner's output, as JSON (`{ assessmentId, tool, content, filename?, repository? }`) or as
  // the file itself in the body (`text/plain`, `text/xml`, `application/x-ndjson`…) with the
  // other fields in the query.
  app.post("/imports", { bodyLimit: IMPORT_BODY_LIMIT, config: { rateLimit: { max: limit.max, timeWindow: limit.timeWindow } } }, async (req, reply) => {
    const input =
      typeof req.body === "string"
        ? { ...validate(ImportQuerySchema, req.query, "query"), content: req.body }
        : validate(ImportBodySchema, req.body, "body");
    if (!input.content) throw new HttpError(400, "invalid body", [{ path: "content", message: "empty" }]);
    const assessment = await requireAssessment(db, input.assessmentId, req.principal);
    return reply.code(201).send(await runImport(db, assessment, input, req.principal, now()));
  });

  app.get("/assessments/:id/imports", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const assessment = await requireAssessment(db, id, req.principal);
    return { items: await listImports(db, assessment.id) };
  });
};
