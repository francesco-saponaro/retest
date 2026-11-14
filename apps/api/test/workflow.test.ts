import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { testApp, type TestApp } from "./app.js";
import { fixture } from "./helpers.js";

/**
 * The workflow: a finding moves through the phases under rules, is set aside as a false positive
 * or an accepted risk with a reason, and is closed by a retest, never by hand. Every move is an
 * audit line. The findings here come from the Nuclei fixture, as they would in the lab.
 */
let t: TestApp;
let aid: string;
let cors: string;
let timestamp: string;

interface F {
  id: string;
  phase: string;
  status: string;
  risk: { severity: string; cvss?: { vector: string; baseScore: number } };
  retest?: { outcome: string; testedAt?: string; notes?: string };
  falsePositiveReason?: string;
  evidence: { id: string; redacted: boolean; source?: unknown }[];
  impact: string;
  fix: string;
  updatedAt: string;
}

interface Line {
  action: string;
  field: string;
  from: string | null;
  to: string | null;
  reason: string | null;
  findingId: string | null;
}

beforeAll(async () => {
  t = await testApp();
});

afterAll(async () => {
  await t.close();
});

const call = (method: "POST" | "PATCH" | "GET", url: string, body?: Record<string, unknown>, sub = "francesco") => (body === undefined ? t.as(sub, { method, url }) : t.as(sub, { method, url, body }));
const finding = async (id: string): Promise<F> => (await call("GET", `/findings/${id}`)).json() as F;
const audit = async (id: string): Promise<Line[]> => ((await call("GET", `/findings/${id}/audit`)).json() as { items: Line[] }).items;
const problem = (res: { json: () => unknown }) => (res.json() as { error: string }).error;

beforeEach(async () => {
  await t.reset();
  aid = await t.assessment("francesco");
  await call("POST", "/imports", { assessmentId: aid, tool: "nuclei", filename: "nuclei/juice-shop.jsonl", content: fixture("nuclei/juice-shop.jsonl") });
  await call("POST", "/imports", { assessmentId: aid, tool: "zap", filename: "zap/juice-shop.json", content: fixture("zap/juice-shop.json") });
  const byTitle = async (q: string) => ((await call("GET", `/assessments/${aid}/findings?q=${encodeURIComponent(q)}`)).json() as { items: { id: string }[] }).items[0]!.id;
  cors = await byTitle("CORS");
  timestamp = await byTitle("Timestamp");
});

const proof = {
  kind: "command-output",
  title: "curl with a foreign Origin",
  content: "$ curl -si -H 'Origin: https://evil.example' http://127.0.0.1:3000/rest/user/whoami | grep -i access-control\nAccess-Control-Allow-Origin: *",
  redacted: true,
};

/** Take the CORS finding through validation and rating, as a person would. */
async function validated(): Promise<void> {
  await call("POST", `/findings/${cors}/evidence`, proof);
  expect((await call("POST", `/findings/${cors}/phase`, { phase: "validation", reason: "Reproduced on all three endpoints." })).status).toBe(200);
}

async function rated(): Promise<void> {
  await validated();
  await call("PATCH", `/findings/${cors}`, {
    impact: "Any website a visitor opens can read the responses of these three endpoints from the visitor's browser; with `*` no cookie is sent, so only public data is exposed.",
    fix: "Echo only the allowed origins in Access-Control-Allow-Origin, or drop the header on these routes.",
    risk: { severity: "medium", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", baseScore: 5.3 } },
  });
  expect((await call("POST", `/findings/${cors}/phase`, { phase: "risk" })).status).toBe(200);
}

describe("POST /findings/:id/phase, with the rules", () => {
  it("refuses validation while the only evidence is the scanner's, and says why", async () => {
    const res = await call("POST", `/findings/${cors}/phase`, { phase: "validation" });
    expect(res.status).toBe(409);
    expect(problem(res)).toMatch(/evidence captured by a person/);
    expect((await finding(cors)).phase).toBe("assessment");
    expect(await audit(cors)).toEqual([]);
  });

  it("moves to validation once a person has added evidence, and audits it", async () => {
    await validated();
    const f = await finding(cors);
    expect(f.phase).toBe("validation");
    expect(f.evidence.filter((e) => !e.source)).toHaveLength(1);
    expect(await audit(cors)).toEqual([expect.objectContaining({ action: "phase", from: "assessment", to: "validation", reason: "Reproduced on all three endpoints." })]);
  });

  it("refuses to skip a phase", async () => {
    await call("POST", `/findings/${cors}/evidence`, proof);
    const res = await call("POST", `/findings/${cors}/phase`, { phase: "risk" });
    expect(res.status).toBe(409);
    expect(problem(res)).toMatch(/one phase at a time/);
  });

  it("refuses remediation until the impact and the fix are written", async () => {
    await validated();
    await call("POST", `/findings/${cors}/phase`, { phase: "risk" });
    const res = await call("POST", `/findings/${cors}/phase`, { phase: "remediation" });
    expect(res.status).toBe(409);
    expect(problem(res)).toMatch(/impact/);
    await call("PATCH", `/findings/${cors}`, { impact: "Public data readable cross-origin.", fix: "Echo allowed origins only." });
    expect((await call("POST", `/findings/${cors}/phase`, { phase: "remediation" })).status).toBe(200);
  });

  it("needs a reason to move back", async () => {
    await validated();
    expect((await call("POST", `/findings/${cors}/phase`, { phase: "assessment" })).status).toBe(409);
    expect((await call("POST", `/findings/${cors}/phase`, { phase: "assessment", reason: "Wrong endpoint in the capture." })).status).toBe(200);
    expect((await audit(cors)).map((l) => l.to)).toEqual(["validation", "assessment"]);
  });
});

describe("POST /findings/:id/status", () => {
  it("marks a false positive with a reason and moves it to validation, since that is where it was found out", async () => {
    const res = await call("POST", `/findings/${timestamp}/status`, { status: "false-positive", reason: "The ten digits are a build number in main.js, not a timestamp." });
    expect(res.status).toBe(200);
    const f = res.json() as F;
    expect(f.status).toBe("false-positive");
    expect(f.falsePositiveReason).toBe("The ten digits are a build number in main.js, not a timestamp.");
    expect(f.phase).toBe("validation");
    expect(await audit(timestamp)).toEqual([
      expect.objectContaining({ action: "phase", from: "assessment", to: "validation" }),
      expect.objectContaining({ action: "status", from: "open", to: "false-positive", reason: "The ten digits are a build number in main.js, not a timestamp." }),
    ]);
    const totals = ((await call("GET", `/assessments/${aid}`)).json() as { totals: { byStatus: Record<string, number>; byPhase: Record<string, number> } }).totals;
    expect(totals.byStatus["false-positive"]).toBe(1);
    expect(totals.byPhase["validation"]).toBe(1);
  });

  it("refuses a false positive without a reason", async () => {
    const res = await call("POST", `/findings/${timestamp}/status`, { status: "false-positive" });
    expect(res.status).toBe(409);
    expect(problem(res)).toMatch(/reason/);
  });

  it("refuses to close by hand", async () => {
    const res = await call("POST", `/findings/${cors}/status`, { status: "closed", reason: "Done." });
    expect(res.status).toBe(409);
    expect(problem(res)).toMatch(/retest/);
  });

  it("accepts a risk only once rated, with a reason, and keeps its phase", async () => {
    expect((await call("POST", `/findings/${cors}/status`, { status: "accepted-risk", reason: "Public data." })).status).toBe(409);
    await rated();
    const res = await call("POST", `/findings/${cors}/status`, { status: "accepted-risk", reason: "The endpoints return public data only; revisit if that changes." });
    expect(res.status).toBe(200);
    expect(res.json()).toMatchObject({ status: "accepted-risk", phase: "risk" });
  });

  it("reopens with a reason and drops the false-positive reason", async () => {
    await call("POST", `/findings/${timestamp}/status`, { status: "false-positive", reason: "A build number." });
    expect((await call("POST", `/findings/${timestamp}/status`, { status: "open" })).status).toBe(409);
    const res = await call("POST", `/findings/${timestamp}/status`, { status: "open", reason: "It changes on every build: it is a timestamp." });
    expect(res.status).toBe(200);
    const f = res.json() as F;
    expect(f.status).toBe("open");
    expect(f.falsePositiveReason).toBeUndefined();
    expect(f.phase).toBe("validation");
  });

  it("refuses an unknown status and is 404 for someone else", async () => {
    expect((await call("POST", `/findings/${cors}/status`, { status: "done" })).status).toBe(400);
    expect((await call("POST", `/findings/${cors}/status`, { status: "false-positive", reason: "x" }, "someone-else")).status).toBe(404);
  });
});

describe("POST /findings/:id/retest", () => {
  const toRemediation = async () => {
    await rated();
    expect((await call("POST", `/findings/${cors}/phase`, { phase: "remediation" })).status).toBe(200);
  };

  it("is refused before remediation, with the phase named", async () => {
    await validated();
    const res = await call("POST", `/findings/${cors}/retest`, { outcome: "fixed", notes: "Header gone." });
    expect(res.status).toBe(409);
    expect(problem(res)).toMatch(/validation/);
  });

  it("needs an outcome that happened and notes on what the checks showed", async () => {
    await toRemediation();
    expect((await call("POST", `/findings/${cors}/retest`, { outcome: "pending", notes: "x" })).status).toBe(409);
    const res = await call("POST", `/findings/${cors}/retest`, { outcome: "fixed" });
    expect(res.status).toBe(400);
    expect((res.json() as { issues: { path: string }[] }).issues.map((i) => i.path)).toEqual(["notes"]);
  });

  it("records a failed retest and leaves the finding open in remediation", async () => {
    await toRemediation();
    const res = await call("POST", `/findings/${cors}/retest`, { outcome: "not-fixed", notes: "The header is still `*` on /rest/user/whoami.", testedAt: "2026-11-14T18:30:00Z" });
    expect(res.status).toBe(200);
    const f = res.json() as F;
    expect(f).toMatchObject({ status: "open", phase: "remediation", retest: { outcome: "not-fixed", testedAt: "2026-11-14T18:30:00.000Z", notes: "The header is still `*` on /rest/user/whoami." } });
    expect((await audit(cors)).at(-1)).toMatchObject({ action: "retest", field: "retest", from: null, to: "not-fixed", reason: "The header is still `*` on /rest/user/whoami." });
  });

  it("closes the finding when the retest finds it fixed, dating it now when no date is given", async () => {
    await toRemediation();
    await call("POST", `/findings/${cors}/retest`, { outcome: "not-fixed", notes: "Still there." });
    const res = await call("POST", `/findings/${cors}/retest`, { outcome: "fixed", notes: "Access-Control-Allow-Origin now echoes only https://juice.local; the foreign origin gets no header." });
    expect(res.status).toBe(200);
    const f = res.json() as F;
    expect(f.status).toBe("closed");
    expect(f.retest?.outcome).toBe("fixed");
    expect(Date.now() - new Date(f.retest!.testedAt!).getTime()).toBeLessThan(10_000);
    const lines = await audit(cors);
    expect(lines.slice(-2)).toEqual([expect.objectContaining({ action: "retest", from: "not-fixed", to: "fixed" }), expect.objectContaining({ action: "status", from: "open", to: "closed" })]);
    // Closed is read-only until reopened.
    expect((await call("POST", `/findings/${cors}/retest`, { outcome: "fixed", notes: "Again." })).status).toBe(409);
    expect((await call("PATCH", `/findings/${cors}`, { impact: "Changed my mind." })).status).toBe(409);
    expect((await call("POST", `/findings/${cors}/phase`, { phase: "risk", reason: "x" })).status).toBe(409);
    expect((await call("POST", `/findings/${cors}/status`, { status: "open", reason: "Regressed in the next release." })).status).toBe(200);
    expect((await finding(cors)).status).toBe("open");
  });

  it("is 404 for someone else", async () => {
    await toRemediation();
    expect((await call("POST", `/findings/${cors}/retest`, { outcome: "fixed", notes: "x" }, "someone-else")).status).toBe(404);
  });
});

describe("what a person decided stays decided", () => {
  it("keeps the vector a person stored even when a tool claimed a worse one", async () => {
    await call("POST", "/imports", { assessmentId: aid, tool: "trivy", filename: "trivy/juice-shop-image.json", content: fixture("trivy/juice-shop-image.json") });
    const jwt = ((await call("GET", `/assessments/${aid}/findings?q=jsonwebtoken`)).json() as { items: { id: string }[] }).items[0]!.id;
    const res = await call("PATCH", `/findings/${jwt}`, { risk: { severity: "critical", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", baseScore: 9.1 } } });
    expect(res.status).toBe(200);
    expect((res.json() as F).risk.cvss?.baseScore).toBe(9.1);
    expect((await finding(jwt)).risk.cvss?.baseScore).toBe(9.1);
  });

  it("keeps a validated finding's risk, phase and text when the same file is imported again, and does not duplicate its evidence", async () => {
    await rated();
    const before = await finding(cors);
    const again = await call("POST", "/imports", { assessmentId: aid, tool: "nuclei", filename: "nuclei/juice-shop.jsonl", content: fixture("nuclei/juice-shop.jsonl") });
    expect(again.status).toBe(201);
    const after = await finding(cors);
    expect(after.risk).toEqual(before.risk);
    expect(after.phase).toBe("risk");
    expect(after.impact).toBe(before.impact);
    expect(after.fix).toBe(before.fix);
    expect(after.evidence).toHaveLength(before.evidence.length);
    const totals = ((await call("GET", `/assessments/${aid}`)).json() as { totals: { findings: number } }).totals;
    expect(totals.findings).toBe(14);
  });

  it("keeps a false positive marked when its tool reports it again", async () => {
    await call("POST", `/findings/${timestamp}/status`, { status: "false-positive", reason: "A build number." });
    await call("POST", "/imports", { assessmentId: aid, tool: "zap", filename: "zap/juice-shop.json", content: fixture("zap/juice-shop.json") });
    expect(await finding(timestamp)).toMatchObject({ status: "false-positive", phase: "validation", falsePositiveReason: "A build number." });
  });

  it("still folds a new tool's sources and evidence into a validated finding", async () => {
    // Validate before ZAP has been seen: the first import above was Nuclei's, so re-run from a fresh assessment.
    await t.reset();
    aid = await t.assessment("francesco");
    await call("POST", "/imports", { assessmentId: aid, tool: "nuclei", content: fixture("nuclei/juice-shop.jsonl") });
    cors = ((await call("GET", `/assessments/${aid}/findings?q=CORS`)).json() as { items: { id: string }[] }).items[0]!.id;
    await validated();
    await call("POST", "/imports", { assessmentId: aid, tool: "zap", content: fixture("zap/juice-shop.json") });
    const f = (await call("GET", `/findings/${cors}`)).json() as F & { sources: { tool: string }[] };
    expect(f.sources.map((s) => s.tool)).toEqual(["nuclei", "zap"]);
    expect(f.phase).toBe("validation");
    expect(f.evidence.filter((e) => !e.source)).toHaveLength(1);
    expect(f.evidence).toHaveLength(3);
  });
});
