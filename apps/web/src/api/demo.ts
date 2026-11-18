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
import { FIXTURES, REAL_RUN } from "./fixtures.js";

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
  // The small network assessment came first, four days ago; it is still in reconnaissance.
  const fourDaysAgo = clock(now).day(4, 16);
  const network = await createAssessment(
    db,
    { name: "Lab network", scope: { targets: ["10.0.10.0/24"], exclusions: [], authorizedBy: DEMO_USER.sub, authorizedAt: fourDaysAgo.toISOString() } },
    DEMO_USER,
    fourDaysAgo,
    "a-lab-network",
  );
  let row = await requireAssessment(db, network.id, DEMO_USER);
  await setAssessmentStatus(db, row, "active", DEMO_USER, "Two lab machines on my own network.", fourDaysAgo);
  row = await requireAssessment(db, network.id, DEMO_USER);
  await setAssessmentPhase(db, row, "recon", DEMO_USER, "Port scan first; nothing is in scope for a web scan yet.", fourDaysAgo);
  row = await requireAssessment(db, network.id, DEMO_USER);
  await runImport(db, row, { assessmentId: row.id, tool: "nmap", content: read("nmap/lab-vms.xml"), filename: "nmap/lab-vms.xml" }, DEMO_USER, fourDaysAgo);

  // The lab was authorised three days ago at nine (UTC) and its six imports followed, two minutes apart.
  await seedLab(db, { ownerId: DEMO_USER.sub, now: clock(now).day(3, 9), read, assessmentId: "a-juice-shop-lab" });
  await walkThrough(db, now);
  await seedRealRun(db);
}

/** When the real run happened: Nmap at 15:20 UTC on 18 Nov 2026, Semgrep a few minutes before it. */
export const REAL_RUN_AT = new Date("2026-11-18T15:10:00Z");

/**
 * The third assessment: what real scanners said about a real Juice Shop, imported unedited. Only
 * Nmap and Semgrep could run on that machine; nobody has validated anything here yet.
 */
async function seedRealRun(db: Db): Promise<void> {
  const at = (minutes: number) => new Date(REAL_RUN_AT.getTime() + minutes * 60 * 1000);
  const created = await createAssessment(
    db,
    {
      name: "Juice Shop, real scan",
      client: "Real Nmap and Semgrep output, 18 Nov 2026",
      scope: { targets: ["127.0.0.1", "http://127.0.0.1:3000", "juice-shop"], exclusions: [], authorizedBy: DEMO_USER.sub, authorizedAt: at(0).toISOString() },
    },
    DEMO_USER,
    at(0),
    "a-juice-shop-real",
  );
  let row = await requireAssessment(db, created.id, DEMO_USER);
  await setAssessmentStatus(db, row, "active", DEMO_USER, "Juice Shop 17.1.1 built from source on my own machine, on 127.0.0.1 only.", at(0));
  row = await requireAssessment(db, created.id, DEMO_USER);
  await setAssessmentPhase(db, row, "assessment", DEMO_USER, "Port 3000 found; the source is in scope too.", at(1));
  row = await requireAssessment(db, created.id, DEMO_USER);
  await runImport(db, row, { assessmentId: row.id, tool: "semgrep", content: REAL_RUN["real-run/semgrep-juice-shop.sarif"]!, filename: "lab/real-run/semgrep-juice-shop.sarif", repository: "juice-shop" }, DEMO_USER, at(2));
  row = await requireAssessment(db, created.id, DEMO_USER);
  await runImport(db, row, { assessmentId: row.id, tool: "nmap", content: REAL_RUN["real-run/nmap-juice-shop.xml"]!, filename: "lab/real-run/nmap-juice-shop.xml" }, DEMO_USER, at(10));
}

const HOUR = 60 * 60 * 1000;

/**
 * Times for the demo's story. Earlier days are fixed hours in UTC, so the report's day-by-day trend
 * always has the same rows; today's moves fall between midnight UTC and now, in order, so nothing
 * lands in the future or slips into fourDaysAgo for someone who opens the demo just after midnight.
 */
export function clock(now: Date) {
  const midnight = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return {
    day: (daysAgo: number, hour: number, minute = 0) => new Date(midnight - daysAgo * 24 * HOUR + hour * HOUR + minute * 60 * 1000),
    /** A point today: 0 is midnight UTC, 1 is now. */
    today: (fraction: number) => new Date(midnight + (now.getTime() - midnight) * fraction),
  };
}

/**
 * Four findings taken through the workflow over the days after the imports, so the lab shows every
 * state of it: one validated and rated, one marked a false positive, one in remediation with a
 * retest that failed, and one fixed and closed by its retest today. Everything below goes through
 * the API's own services and their rules; the evidence is what the lab's own commands print. The
 * lab is remade on every reload.
 */
export async function walkThrough(db: Db, now: Date): Promise<void> {
  const who = DEMO_USER;
  const when = clock(now);
  const find = async (id: string) => (await requireFinding(db, id, who)).finding;
  // Two days ago: the CORS finding, the false positive and the root account's MFA. Yesterday: the jsonwebtoken CVE. Today: the MFA retest.
  const at = (step: number) => [when.day(2, 10), when.day(2, 10, 30), when.day(2, 11), when.day(2, 14), when.day(1, 10), when.day(1, 10, 40), when.day(1, 11)][step]!;

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
        "$ for p in '/rest/products/search?q=' /api/Quantitys/; do curl -si -H 'Origin: https://evil.example' \"http://127.0.0.1:3000$p\" | grep -i access-control; done",
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Origin: *",
      ].join("\n"),
      redacted: true,
      capturedAt: at(0).toISOString(),
    },
    at(0),
  );
  await setFindingPhase(db, await find(cors), "validation", who, "Reproduced against all three endpoints: the header is * and no Access-Control-Allow-Credentials is sent.", at(0));
  await updateFinding(
    db,
    await find(cors),
    {
      impact:
        "Any website a visitor opens can read the responses of these three endpoints from the visitor's browser. Because the header is *, the browser sends no cookie and no Authorization header with the cross-origin request, so what a third-party page can read is what an anonymous user can already read: the product list, the quantities, and the empty user that /rest/user/whoami gives anyone without a token. It becomes serious the day an endpoint behind this header returns private data, or the day the header reflects the origin with Access-Control-Allow-Credentials: true.",
      risk: { severity: "medium", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", baseScore: 5.3 } },
    },
    at(1),
  );
  await setFindingPhase(db, await find(cors), "risk", who, "Confidentiality low: the data behind the header is public anyway.", at(1));

  // ZAP's timestamp alert on main.js: a number that looks like a date, checked and set aside.
  await setFindingStatus(db, await find("f-83eaab78bf12"), "false-positive", who, "The ten digits ZAP matched in main.js are a constant in the minified Angular bundle, the same on every request; nothing about the server's clock is disclosed.", at(3));

  // The jsonwebtoken CVE: confirmed in the container, written up, and retested against the same image.
  const jwt = "f-7f910fa0b432";
  await addEvidence(
    db,
    await find(jwt),
    {
      kind: "command-output",
      title: "npm ls in the Juice Shop folder",
      content: ["$ npm ls jsonwebtoken", "juice-shop@17.1.1 ~/lab/juice-shop", "+-- express-jwt@0.1.3", "| `-- jsonwebtoken@0.1.0", "`-- jsonwebtoken@0.4.0"].join("\n"),
      redacted: true,
      capturedAt: at(4).toISOString(),
    },
    at(4),
  );
  await setFindingPhase(db, await find(jwt), "validation", who, "The vulnerable version is installed, and lib/insecurity.ts verifies every authenticated request with it.", at(4));
  await updateFinding(
    db,
    await find(jwt),
    {
      impact:
        "jsonwebtoken 0.4.0 lets the token choose the algorithm. The app verifies with an RSA public key that it also serves to the browser, so a token signed with HS256 using that public key as the secret passes verification. Anyone can forge a token for any account, the admin's included, and every authenticated route accepts it.",
      fix: "Upgrade jsonwebtoken to 9.x and pass algorithms: ['RS256'] to verify, so the algorithm is the server's choice and not the token's. Check: a token signed HS256 with the public key must be refused.",
    },
    at(5),
  );
  await setFindingPhase(db, await find(jwt), "risk", who, undefined, at(5));
  await setFindingPhase(db, await find(jwt), "remediation", who, undefined, at(5));
  await recordRetest(db, await find(jwt), { outcome: "not-fixed", notes: "The image still ships jsonwebtoken 0.4.0 and the forged HS256 token is still accepted. Juice Shop pins the version on purpose, so this stays open until the lab runs a patched build." }, who, at(6));

  // The root account without MFA: confirmed from the account summary, rated for this lab, fixed by the
  // account's owner, and closed today by a retest that reads the same value again.
  const mfa = "f-ab755454eaf7";
  const summary = (enabled: 0 | 1) => ["$ aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'", String(enabled)].join("\n");
  await addEvidence(db, await find(mfa), { kind: "command-output", title: "MFA on the root user, before", content: summary(0), redacted: true, capturedAt: when.day(2, 14).toISOString() }, when.day(2, 14));
  await setFindingPhase(db, await find(mfa), "validation", who, "AccountMFAEnabled is 0: the root user signs in with a password alone.", when.day(2, 14));
  await updateFinding(
    db,
    await find(mfa),
    {
      impact:
        "Whoever learns the root user's password owns the whole account: every bucket, every key, the billing, and the power to delete the trail that would show it. Nothing asks for a second factor. The root user was last used two days ago, so the password is in someone's hands.",
      fix: "Turn on MFA for the root user (a hardware key or an authenticator app), keep the device somewhere safe, and stop using root for daily work. Check: AccountMFAEnabled reads 1.",
      risk: { severity: "critical", likelihood: "medium", impact: "high" },
    },
    when.day(2, 14, 20),
  );
  await setFindingPhase(db, await find(mfa), "risk", who, undefined, when.day(2, 14, 20));
  await setFindingPhase(db, await find(mfa), "remediation", who, "Asked the account's owner to enable MFA on root.", when.day(2, 14, 30));
  await addEvidence(db, await find(mfa), { kind: "command-output", title: "MFA on the root user, after", content: summary(1), redacted: true, capturedAt: when.today(0.5).toISOString() }, when.today(0.5));
  await recordRetest(db, await find(mfa), { outcome: "fixed", notes: "AccountMFAEnabled now reads 1; a root sign-in asks for the authenticator code.", testedAt: when.today(0.6).toISOString() }, who, when.today(0.6));
}
