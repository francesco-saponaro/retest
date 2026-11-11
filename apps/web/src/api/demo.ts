import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import type { Principal } from "@retest/api/auth.js";
import * as schema from "@retest/api/db/schema.js";
import type { Db } from "@retest/api/db/index.js";
import { HttpError } from "@retest/api/http.js";
import { seedLab } from "@retest/api/lab.js";
import { toAssessment } from "@retest/api/rows.js";
import { createAssessment, listAssessments, loadAssessment, requireAssessment, setAssessmentPhase, setAssessmentStatus, totals } from "@retest/api/services/assessments.js";
import { listAssets } from "@retest/api/services/assets.js";
import { listAudit } from "@retest/api/services/audit.js";
import { FindingPatchSchema, FindingsQuerySchema, findingDetail, listFindings, requireFinding, updateFinding } from "@retest/api/services/findings.js";
import { listImports, runImport } from "@retest/api/services/imports.js";
import { validate } from "@retest/api/http.js";
import tables from "../../../api/drizzle/0000_tables.sql?raw";
import { ApiError, PAGE, type ApiClient } from "./client.js";
import { FIXTURES } from "./fixtures.js";

/**
 * The demo: the API's own services, running in the browser against PostgreSQL compiled to
 * WebAssembly, seeded through the same import pipeline from the fixtures the build ships. There
 * is no server, no token and no persistence; the data is made when the page loads and goes away
 * with the tab. Everything the screens show is what the real API would show for the same files.
 */
export interface DemoClient extends ApiClient {
  close(): Promise<void>;
}

/** The person the demo signs in as. Nothing checks a token here: there is no network to come in on. */
export const DEMO_USER: Principal = { sub: "demo", role: "assessor" };

const DAY = 24 * 60 * 60 * 1000;

export async function demoClient(seededAt = new Date(), now: () => Date = () => new Date()): Promise<DemoClient> {
  const pg = new PGlite();
  const db: Db = drizzle(pg, { schema });
  await pg.exec(tables);
  await seedDemo(db, seededAt);

  const who = DEMO_USER;
  const call = async <T>(fn: () => Promise<T>): Promise<T> => {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof HttpError) throw new ApiError(e.status, e.message);
      throw e;
    }
  };

  return {
    mode: "demo",
    listAssessments: () => call(() => listAssessments(db, who)),
    getAssessment: (id) =>
      call(async () => {
        const row = await loadAssessment(db, id, who);
        if (!row) throw new ApiError(404, "assessment not found");
        return { ...toAssessment(row), totals: await totals(db, row.id) };
      }),
    listAssets: (id) => call(async () => listAssets(db, (await requireAssessment(db, id, who)).id)),
    listImports: (id) => call(async () => listImports(db, (await requireAssessment(db, id, who)).id)),
    listAudit: (id) => call(async () => listAudit(db, (await requireAssessment(db, id, who)).id)),
    // The same validation the routes run, so a bad filter or a bad patch is refused with the same 400.
    listFindings: (id, filter) =>
      call(async () => {
        const set = Object.fromEntries(Object.entries(filter).filter(([, v]) => v));
        const query = validate(FindingsQuerySchema, { ...set, limit: String(PAGE) }, "query");
        const page = await listFindings(db, (await requireAssessment(db, id, who)).id, query);
        return { ...page, limit: query.limit, offset: query.offset };
      }),
    getFinding: (fid) => call(async () => findingDetail(db, (await requireFinding(db, fid, who)).finding)),
    updateFinding: (fid, patch) =>
      call(async () => {
        const body = validate(FindingPatchSchema, patch, "body");
        return updateFinding(db, (await requireFinding(db, fid, who)).finding, body, now());
      }),
    close: () => pg.close(),
  };
}

/** The Juice Shop lab as the API seeds it, and a second, smaller assessment still in reconnaissance. */
async function seedDemo(db: Db, now: Date): Promise<void> {
  const read = (file: string): string => {
    const text = FIXTURES[file];
    if (text === undefined) throw new Error(`no bundled fixture ${file}`);
    return text;
  };
  const yesterday = new Date(now.getTime() - DAY);
  const network = await createAssessment(
    db,
    { name: "Lab network", scope: { targets: ["10.0.10.0/24"], exclusions: [], authorizedBy: DEMO_USER.sub, authorizedAt: yesterday.toISOString() } },
    DEMO_USER,
    yesterday,
    "a-lab-network",
  );
  let row = await requireAssessment(db, network.id, DEMO_USER);
  await setAssessmentStatus(db, row, "active", DEMO_USER, "Two lab machines on my own network.", yesterday);
  row = await requireAssessment(db, network.id, DEMO_USER);
  await setAssessmentPhase(db, row, "recon", DEMO_USER, "Port scan first; nothing is in scope for a web scan yet.", yesterday);
  row = await requireAssessment(db, network.id, DEMO_USER);
  await runImport(db, row, { assessmentId: row.id, tool: "nmap", content: read("nmap/lab-vms.xml"), filename: "nmap/lab-vms.xml" }, DEMO_USER, yesterday);

  // The lab was authorised a quarter of an hour ago and its six imports followed, two minutes apart.
  await seedLab(db, { ownerId: DEMO_USER.sub, now: new Date(now.getTime() - 15 * 60 * 1000), read, assessmentId: "a-juice-shop-lab" });
}
