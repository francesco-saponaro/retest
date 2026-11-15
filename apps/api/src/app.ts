import rateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyError, type FastifyInstance, type FastifyRequest } from "fastify";
import { ZodError } from "zod";
import { AuthError, bearerToken, verifyToken, type Principal } from "./auth.js";
import type { Db } from "./db/index.js";
import { HttpError, issuesOf } from "./http.js";
import { assessmentRoutes } from "./routes/assessments.js";
import { assetRoutes } from "./routes/assets.js";
import { findingRoutes } from "./routes/findings.js";
import { importRoutes } from "./routes/imports.js";
import { reportRoutes } from "./routes/reports.js";

type AuthResult = { principal: Principal; error?: undefined } | { principal?: undefined; error: string };

declare module "fastify" {
  interface FastifyRequest {
    /** Set by the auth hook on every route but /health. */
    principal: Principal;
    /** What the token said, read once per request. */
    auth: AuthResult | undefined;
  }
}

export interface AppOptions {
  db: Db;
  /** The HS256 secret every token is checked against. At least 32 characters. */
  jwtSecret: string;
  /** Requests per window per caller (the token's `sub`, or the address before authentication). */
  rateLimit?: { max: number; timeWindow: string | number };
  /** A tighter limit for imports, which parse files. */
  importRateLimit?: { max: number; timeWindow: string | number };
  logger?: boolean;
  /** The time, for tests. */
  now?: () => Date;
}

/** The largest file an import accepts. */
export const IMPORT_BODY_LIMIT = 20 * 1024 * 1024;

export async function buildApp(options: AppOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: options.logger ?? true, bodyLimit: 1024 * 1024 });
  const now = options.now ?? (() => new Date());

  app.decorateRequest("principal", null as unknown as Principal);
  app.decorateRequest("auth", undefined);

  /** The token is read once per request, here, and the result is used by the rate limiter and the auth hook. */
  const authenticate = async (req: FastifyRequest): Promise<AuthResult> => {
    if (req.auth) return req.auth;
    const token = bearerToken(req.headers.authorization);
    if (!token) return (req.auth = { error: "missing token" });
    try {
      return (req.auth = { principal: await verifyToken(token, options.jwtSecret) });
    } catch (e) {
      if (e instanceof AuthError) return (req.auth = { error: e.message });
      throw e;
    }
  };

  // Every answer, refusals and errors included. The API serves JSON and markdown, never a page, so
  // nothing it sends should be framed, sniffed into HTML, kept by a shared cache or followed by a referrer.
  // There is no CORS on purpose: the web app reaches the API through its own origin.
  app.addHook("onSend", async (_req, reply) => {
    reply.header("x-content-type-options", "nosniff");
    reply.header("cache-control", "no-store");
    reply.header("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
    reply.header("referrer-policy", "no-referrer");
  });

  // Rate limiting runs before anything else, including authentication, so that a flood of bad
  // tokens is counted too. A valid token is counted per user; anything else per address.
  const keyGenerator = async (req: FastifyRequest): Promise<string> => {
    const auth = await authenticate(req);
    return auth.principal ? `user:${auth.principal.sub}` : `ip:${req.ip}`;
  };
  await app.register(rateLimit, {
    global: false,
    max: options.rateLimit?.max ?? 300,
    timeWindow: options.rateLimit?.timeWindow ?? "1 minute",
    keyGenerator,
  });
  app.addHook("onRequest", app.rateLimit());

  // Scanner output arrives as text: Nmap XML, Nuclei JSON Lines, SARIF. Keep it as a string.
  app.addContentTypeParser(["text/plain", "text/xml", "application/xml", "application/x-ndjson", "application/jsonl", "application/octet-stream"], { parseAs: "string" }, (_req, body, done) => done(null, body));

  app.get("/health", { config: { public: true } }, async () => ({ ok: true }));

  // Authentication. A route is public only when it says so.
  app.addHook("onRequest", async (req, reply) => {
    if ((req.routeOptions.config as { public?: boolean }).public) return;
    const auth = await authenticate(req);
    if (!auth.principal) return reply.code(401).send({ error: auth.error });
    req.principal = auth.principal;
  });

  app.setErrorHandler((error: FastifyError | HttpError | ZodError, _req, reply) => {
    if (error instanceof HttpError) {
      return reply.code(error.status).send({ error: error.message, ...(error.issues ? { issues: error.issues } : {}) });
    }
    if (error instanceof ZodError) {
      // A schema refused something after validation: a risk whose severity disagrees with its CVSS, a finding closed without a retest.
      return reply.code(400).send({ error: "invalid data", issues: issuesOf(error) });
    }
    const status = (error as FastifyError).statusCode ?? 500;
    if (status >= 500) {
      app.log.error(error);
      return reply.code(status).send({ error: "internal error" });
    }
    // Fastify's own 4xx: a body that is not JSON, a body too large, too many requests.
    return reply.code(status).send({ error: error.message });
  });

  app.setNotFoundHandler((_req, reply) => reply.code(404).send({ error: "not found" }));

  const ctx = { db: options.db, now };
  await app.register(assessmentRoutes, ctx);
  await app.register(assetRoutes, ctx);
  await app.register(findingRoutes, ctx);
  await app.register(importRoutes, { ...ctx, rateLimit: { ...(options.importRateLimit ?? { max: 20, timeWindow: "1 minute" }), keyGenerator } });
  await app.register(reportRoutes, ctx);

  return app;
}

export interface RouteContext {
  db: Db;
  now: () => Date;
}
