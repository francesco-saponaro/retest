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
import {
  EvidencePatchSchema,
  FindingPatchSchema,
  FindingPhaseSchema,
  FindingStatusChangeSchema,
  FindingsQuerySchema,
  NewEvidenceSchema,
  RetestBodySchema,
  addEvidence,
  findingDetail,
  listFindings,
  recordRetest,
  requireEvidence,
  requireFinding,
  setFindingPhase,
  setFindingStatus,
  updateEvidence,
  updateFinding,
} from "@retest/api/services/findings.js";
import { listImports, runImport } from "@retest/api/services/imports.js";
import { reportModel } from "@retest/api/services/reports.js";
import { summaryMarkdown, technicalMarkdown } from "@retest/api/report/markdown.js";
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
    setFindingPhase: (fid, change) =>
      call(async () => {
        const { phase, reason } = validate(FindingPhaseSchema, change, "body");
        return setFindingPhase(db, (await requireFinding(db, fid, who)).finding, phase, who, reason, now());
      }),
    setFindingStatus: (fid, change) =>
      call(async () => {
        const { status, reason } = validate(FindingStatusChangeSchema, change, "body");
        return setFindingStatus(db, (await requireFinding(db, fid, who)).finding, status, who, reason, now());
      }),
    recordRetest: (fid, input) =>
      call(async () => {
        const body = validate(RetestBodySchema, input, "body");
        return recordRetest(db, (await requireFinding(db, fid, who)).finding, body, who, now());
      }),
    addEvidence: (fid, input) =>
      call(async () => {
        const body = validate(NewEvidenceSchema, input, "body");
        return addEvidence(db, (await requireFinding(db, fid, who)).finding, body, now());
      }),
    updateEvidence: (eid, patch) =>
      call(async () => {
        const body = validate(EvidencePatchSchema, patch, "body");
        return updateEvidence(db, (await requireEvidence(db, eid, who)).evidence, body);
      }),
    listFindingAudit: (fid) =>
      call(async () => {
        const { finding } = await requireFinding(db, fid, who);
        return listAudit(db, finding.assessmentId, finding.id);
      }),
    getReport: (id) => call(async () => reportModel(db, await requireAssessment(db, id, who), now())),
    getReportMarkdown: (id, kind) =>
      call(async () => {
        const report = await reportModel(db, await requireAssessment(db, id, who), now());
        return kind === "summary" ? summaryMarkdown(report) : technicalMarkdown(report);
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
  await walkThrough(db, now);
}

const MINUTE = 60 * 1000;

/**
 * Three findings taken through the workflow after the imports, so the lab shows every state of it:
 * one validated and rated, one marked a false positive, one in remediation with a retest that
 * failed. Everything below goes through the API's own services and their rules; the evidence is
 * what the lab's own commands print. Nothing is closed: the retest that closes one is left for
 * whoever reads the finding, and the lab is remade on every reload.
 */
export async function walkThrough(db: Db, now: Date): Promise<void> {
  const who = DEMO_USER;
  const at = (minutesAgo: number) => new Date(now.getTime() - minutesAgo * MINUTE);
  const find = async (id: string) => (await requireFinding(db, id, who)).finding;

  // CORS: reproduced by hand, rated by the vector chapter 6 works out, waiting to be written up.
  const cors = "f-9c67368df231";
  await addEvidence(
    db,
    await find(cors),
    {
      kind: "command-output",
      title: "curl with a foreign Origin",
      content: [
        "$ curl -si -H 'Origin: https://evil.example' http://127.0.0.1:3000/rest/user/whoami",
        "HTTP/1.1 200 OK",
        "Access-Control-Allow-Origin: *",
        "Content-Type: application/json; charset=utf-8",
        "",
        '{"user":{}}',
        "",
        "$ for p in /rest/products/search?q= /api/Quantitys/; do curl -si -H 'Origin: https://evil.example' \"http://127.0.0.1:3000$p\" | grep -i access-control; done",
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Origin: *",
      ].join("\n"),
      redacted: true,
      capturedAt: at(4).toISOString(),
    },
    at(4),
  );
  await setFindingPhase(db, await find(cors), "validation", who, "Reproduced against all three endpoints: the header is * and no Access-Control-Allow-Credentials is sent.", at(4));
  await updateFinding(
    db,
    await find(cors),
    {
      impact:
        "Any website a visitor opens can read the responses of these three endpoints from the visitor's browser. Because the header is *, the browser sends no cookie and no Authorization header with the cross-origin request, so what a third-party page can read is what an anonymous user can already read: the product list, the quantities, and the empty user that /rest/user/whoami gives anyone without a token. It becomes serious the day an endpoint behind this header returns private data, or the day the header reflects the origin with Access-Control-Allow-Credentials: true.",
      risk: { severity: "medium", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", baseScore: 5.3 } },
    },
    at(3),
  );
  await setFindingPhase(db, await find(cors), "risk", who, "Confidentiality low: the data behind the header is public anyway.", at(3));

  // ZAP's timestamp alert on main.js: a number that looks like a date, checked and set aside.
  await setFindingStatus(db, await find("f-83eaab78bf12"), "false-positive", who, "The ten digits ZAP matched in main.js are a constant in the minified Angular bundle, the same on every request; nothing about the server's clock is disclosed.", at(2));

  // The jsonwebtoken CVE: confirmed in the container, written up, and retested against the same image.
  const jwt = "f-7f910fa0b432";
  await addEvidence(
    db,
    await find(jwt),
    {
      kind: "command-output",
      title: "npm ls in the container",
      content: ["$ docker compose exec juice-shop npm ls jsonwebtoken", "juice-shop@17.1.1 /juice-shop", "├─┬ express-jwt@0.1.3", "│ └── jsonwebtoken@0.4.0", "└── jsonwebtoken@0.4.0"].join("\n"),
      redacted: true,
      capturedAt: at(2).toISOString(),
    },
    at(2),
  );
  await setFindingPhase(db, await find(jwt), "validation", who, "The vulnerable version is installed, and lib/insecurity.ts verifies every authenticated request with it.", at(2));
  await updateFinding(
    db,
    await find(jwt),
    {
      impact:
        "jsonwebtoken 0.4.0 lets the token choose the algorithm. The app verifies with an RSA public key that it also serves to the browser, so a token signed with HS256 using that public key as the secret passes verification. Anyone can forge a token for any account, the admin's included, and every authenticated route accepts it.",
      fix: "Upgrade jsonwebtoken to 9.x and pass algorithms: ['RS256'] to verify, so the algorithm is the server's choice and not the token's. Check: a token signed HS256 with the public key must be refused.",
    },
    at(1),
  );
  await setFindingPhase(db, await find(jwt), "risk", who, undefined, at(1));
  await setFindingPhase(db, await find(jwt), "remediation", who, undefined, at(1));
  await recordRetest(db, await find(jwt), { outcome: "not-fixed", notes: "The image still ships jsonwebtoken 0.4.0 and the forged HS256 token is still accepted. Juice Shop pins the version on purpose, so this stays open until the lab runs a patched build." }, who, at(1));
}
