import type { FastifyInstance, InjectOptions } from "fastify";
import { buildApp, type AppOptions } from "../src/app.js";
import { signToken, type Role } from "../src/auth.js";
import { testDb, type TestDb } from "./helpers.js";

export const TEST_SECRET = "a-test-secret-that-is-long-enough-to-be-allowed";

export interface TestApp extends TestDb {
  app: FastifyInstance;
  /** A token for a user. */
  token: (sub: string, role?: Role) => Promise<string>;
  /** Inject a request as a user. `body` is sent as JSON unless `payload` is given. */
  as: (sub: string, options: InjectOptions & { body?: unknown; role?: Role }) => Promise<{ status: number; json: () => unknown; text: string; headers: Record<string, string | string[] | number | undefined> }>;
  /** The usual: create an assessment for a user, return its id. */
  assessment: (sub: string, overrides?: Record<string, unknown>) => Promise<string>;
}

export async function testApp(options: Partial<AppOptions> = {}): Promise<TestApp> {
  const t = await testDb();
  // The limits are high here so that a test file can make as many requests as it likes; `ratelimit.test.ts` sets its own.
  const app = await buildApp({
    db: t.db,
    jwtSecret: TEST_SECRET,
    logger: false,
    rateLimit: { max: 10000, timeWindow: "1 minute" },
    importRateLimit: { max: 10000, timeWindow: "1 minute" },
    ...options,
  });
  await app.ready();
  const token = (sub: string, role?: Role) => signToken({ sub, ...(role ? { role } : {}) }, TEST_SECRET);
  const as: TestApp["as"] = async (sub, { body, role, headers, ...rest }) => {
    const res = await app.inject({
      ...rest,
      headers: { authorization: `Bearer ${await token(sub, role)}`, ...(body !== undefined ? { "content-type": "application/json" } : {}), ...headers },
      ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
    });
    return { status: res.statusCode, json: () => res.json(), text: res.body, headers: res.headers };
  };
  const assessment: TestApp["assessment"] = async (sub, overrides = {}) => {
    const res = await as(sub, {
      method: "POST",
      url: "/assessments",
      body: { name: "Lab", scope: { targets: ["127.0.0.1", "http://127.0.0.1:3000"], authorizedBy: "me" }, ...overrides },
    });
    if (res.status !== 201) throw new Error(`could not create the assessment: ${res.text}`);
    return (res.json() as { id: string }).id;
  };
  return {
    ...t,
    app,
    token,
    as,
    assessment,
    close: async () => {
      await app.close();
      await t.close();
    },
  };
}
