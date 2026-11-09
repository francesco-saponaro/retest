import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import type { RouteContext } from "../app.js";
import { validate } from "../http.js";
import {
  AssessmentPatchSchema,
  NewAssessmentSchema,
  PhaseChangeSchema,
  StatusChangeSchema,
  createAssessment,
  deleteAssessment,
  listAssessments,
  requireAssessment,
  setAssessmentPhase,
  setAssessmentStatus,
  totals,
  updateAssessment,
} from "../services/assessments.js";
import { listAudit } from "../services/audit.js";
import { toAssessment } from "../rows.js";

export const IdParams = z.object({ id: z.string().min(1).max(100) });

export const assessmentRoutes: FastifyPluginAsync<RouteContext> = async (app, { db, now }) => {
  app.post("/assessments", async (req, reply) => {
    const input = validate(NewAssessmentSchema, req.body, "body");
    const created = await createAssessment(db, input, req.principal, now());
    return reply.code(201).send(created);
  });

  app.get("/assessments", async (req) => ({ items: await listAssessments(db, req.principal) }));

  app.get("/assessments/:id", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const row = await requireAssessment(db, id, req.principal);
    return { ...toAssessment(row), totals: await totals(db, row.id) };
  });

  app.patch("/assessments/:id", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const patch = validate(AssessmentPatchSchema, req.body, "body");
    const row = await requireAssessment(db, id, req.principal);
    return updateAssessment(db, row, patch, now());
  });

  app.post("/assessments/:id/phase", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const { phase, reason } = validate(PhaseChangeSchema, req.body, "body");
    const row = await requireAssessment(db, id, req.principal);
    return setAssessmentPhase(db, row, phase, req.principal, reason, now());
  });

  app.post("/assessments/:id/status", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const { status, reason } = validate(StatusChangeSchema, req.body, "body");
    const row = await requireAssessment(db, id, req.principal);
    return setAssessmentStatus(db, row, status, req.principal, reason, now());
  });

  app.get("/assessments/:id/audit", async (req) => {
    const { id } = validate(IdParams, req.params, "params");
    const row = await requireAssessment(db, id, req.principal);
    return { items: await listAudit(db, row.id) };
  });

  app.delete("/assessments/:id", async (req, reply) => {
    const { id } = validate(IdParams, req.params, "params");
    const row = await requireAssessment(db, id, req.principal);
    await deleteAssessment(db, row);
    return reply.code(204).send();
  });
};
