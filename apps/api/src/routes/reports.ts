import type { FastifyPluginAsync } from "fastify";
import type { RouteContext } from "../app.js";
import { validate } from "../http.js";
import { requireAssessment } from "../services/assessments.js";
import { executiveSummary, technicalReport } from "../services/reports.js";
import { IdParams } from "./assessments.js";

export const reportRoutes: FastifyPluginAsync<RouteContext> = async (app, { db }) => {
  app.get("/assessments/:id/report.md", async (req, reply) => {
    const { id } = validate(IdParams, req.params, "params");
    const assessment = await requireAssessment(db, id, req.principal);
    return reply.type("text/markdown; charset=utf-8").send(await technicalReport(db, assessment));
  });

  app.get("/assessments/:id/summary.md", async (req, reply) => {
    const { id } = validate(IdParams, req.params, "params");
    const assessment = await requireAssessment(db, id, req.principal);
    return reply.type("text/markdown; charset=utf-8").send(await executiveSummary(db, assessment));
  });
};
