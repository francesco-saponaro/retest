import type { FastifyPluginAsync } from "fastify";
import type { z } from "zod";
import type { RouteContext } from "../app.js";
import { HttpError, validate } from "../http.js";
import { requireAssessment } from "../services/assessments.js";
import { listAudit } from "../services/audit.js";
import {
  EvidencePatchSchema,
  EvidenceQuerySchema,
  FindingPatchSchema,
  FindingPhaseSchema,
  FindingsQuerySchema,
  NewEvidenceSchema,
  NewFindingSchema,
  addEvidence,
  createFinding,
  findingDetail,
  listFindings,
  requireEvidence,
  requireFinding,
  setFindingPhase,
  updateEvidence,
  updateFinding,
} from "../services/findings.js";
import { IdParams } from "./assessments.js";

export const findingRoutes: FastifyPluginAsync<RouteContext> = async (app, { db, now }) => {
  app.post("/assessments/:id/findings", async (req, reply) => {
    const { id } = validate(IdParams, req.params, "params");
    const input = validate(NewFindingSchema, req.body, "body");
    const assessment = await requireAssessment(db, id, req.principal);
    return reply.code(201).send(await createFinding(db, assessment, input, req.principal, now()));
  });

  app.get("/assessments/:id/findings", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const query = validate(FindingsQuerySchema, req.query, "query");
    const assessment = await requireAssessment(db, id, req.principal);
    const page = await listFindings(db, assessment.id, query);
    return { ...page, limit: query.limit, offset: query.offset };
  });

  app.get("/findings/:id", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const { finding } = await requireFinding(db, id, req.principal);
    return findingDetail(db, finding);
  });

  app.patch("/findings/:id", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const patch = validate(FindingPatchSchema, req.body, "body");
    const { finding } = await requireFinding(db, id, req.principal);
    return updateFinding(db, finding, patch, now());
  });

  app.post("/findings/:id/phase", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const { phase, reason } = validate(FindingPhaseSchema, req.body, "body");
    const { finding } = await requireFinding(db, id, req.principal);
    return setFindingPhase(db, finding, phase, req.principal, reason, now());
  });

  app.get("/findings/:id/audit", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const { finding } = await requireFinding(db, id, req.principal);
    return { items: await listAudit(db, finding.assessmentId, finding.id) };
  });

  // Evidence as JSON (`{ kind, title, content, redacted, capturedAt }`) or as a plain-text body
  // with `?kind=` and `?title=`, so a capture can be piped straight in from the terminal.
  app.post("/findings/:id/evidence", { bodyLimit: 5 * 1024 * 1024 }, async (req, reply) => {
    const { id } = validate(IdParams, req.params, "params");
    const input: z.infer<typeof NewEvidenceSchema> =
      typeof req.body === "string"
        ? { ...validate(EvidenceQuerySchema, req.query, "query"), content: req.body, redacted: false }
        : validate(NewEvidenceSchema, req.body, "body");
    if (!input.content) throw new HttpError(400, "invalid body", [{ path: "content", message: "empty" }]);
    const { finding } = await requireFinding(db, id, req.principal);
    return reply.code(201).send(await addEvidence(db, finding, input, now()));
  });

  app.patch("/evidence/:id", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const patch = validate(EvidencePatchSchema, req.body, "body");
    const { evidence } = await requireEvidence(db, id, req.principal);
    return updateEvidence(db, evidence, patch);
  });
};
