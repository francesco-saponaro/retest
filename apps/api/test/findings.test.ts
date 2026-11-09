import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { testApp, type TestApp } from "./app.js";

let t: TestApp;
let aid: string;
let shop: string;
let box: string;

beforeAll(async () => {
  t = await testApp();
});

afterAll(async () => {
  await t.close();
});

beforeEach(async () => {
  await t.reset();
  aid = await t.assessment("francesco");
  shop = ((await t.as("francesco", { method: "POST", url: `/assessments/${aid}/assets`, body: { kind: "web-app", name: "Juice Shop", url: "http://127.0.0.1:3000" } })).json() as { id: string }).id;
  box = ((await t.as("francesco", { method: "POST", url: `/assessments/${aid}/assets`, body: { kind: "host", name: "box", host: "10.0.10.11" } })).json() as { id: string }).id;
});

const bola = () => ({
  title: "Any user can read any basket",
  assetId: shop,
  scope: "GET /rest/basket/:id",
  impact: "A logged-in user who changes the id in the URL reads another customer's basket, including the products and the coupon.",
  fix: "Load the basket by the id in the token, not by the id in the URL, and return 403 when they differ.",
  risk: { severity: "high", likelihood: "high", impact: "medium" },
  phase: "validation",
  mappings: { cwe: [639] },
});

async function create(body: Record<string, unknown> = bola(), sub = "francesco") {
  const res = await t.as(sub, { method: "POST", url: `/assessments/${aid}/findings`, body });
  return res;
}

describe("POST /assessments/:id/findings (a finding made by hand)", () => {
  it("creates a manual finding with the seven fields and maps it from its CWE", async () => {
    const res = await create();
    expect(res.status).toBe(201);
    const f = res.json() as Record<string, unknown>;
    expect(f["id"]).toMatch(/^f-[0-9a-f]{12}$/);
    expect(f).toMatchObject({
      assessmentId: aid,
      assetId: shop,
      phase: "validation",
      status: "open",
      evidence: [],
      sources: [{ tool: "manual", rawId: expect.stringMatching(/^manual-/) }],
      mappings: { cwe: [639], cve: [], owaspTop10: ["A01"], owaspApi: ["API1"], asvs: ["V4"], cis: [6, 16] },
    });
  });

  it("refuses an asset of another assessment, or none", async () => {
    const other = await t.assessment("francesco");
    const elsewhere = ((await t.as("francesco", { method: "POST", url: `/assessments/${other}/assets`, body: { kind: "host", name: "x", host: "10.9.9.9" } })).json() as { id: string }).id;
    const res = await create({ ...bola(), assetId: elsewhere });
    expect(res.status).toBe(400);
    expect((res.json() as { issues: { path: string }[] }).issues.map((i) => i.path)).toEqual(["assetId"]);
    expect((await create({ ...bola(), assetId: "asset-nope" })).status).toBe(400);
  });

  it("refuses a severity that disagrees with the CVSS vector", async () => {
    const res = await create({ ...bola(), risk: { severity: "low", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", baseScore: 6.5 } } });
    expect(res.status).toBe(400);
    expect((res.json() as { issues: { path: string }[] }).issues.map((i) => i.path)).toContain("risk.severity");
  });

  it("refuses a closed finding, a status or a retest at creation", async () => {
    const res = await create({ ...bola(), status: "closed" });
    expect(res.status).toBe(400);
  });

  it("refuses a finding on a closed assessment", async () => {
    await t.as("francesco", { method: "POST", url: `/assessments/${aid}/status`, body: { status: "closed" } });
    expect((await create()).status).toBe(409);
  });

  it("is 404 on someone else's assessment", async () => {
    expect((await create(bola(), "someone-else")).status).toBe(404);
  });
});

describe("GET /assessments/:id/findings", () => {
  beforeEach(async () => {
    await create();
    await create({ ...bola(), title: "Open port 22", assetId: box, scope: "tcp/22", risk: { severity: "info" }, phase: "recon", mappings: {} });
    await create({ ...bola(), title: "CSP header missing", scope: "GET /", risk: { severity: "medium" }, phase: "assessment", mappings: { cwe: [693] } });
  });

  it("lists the findings of the assessment, most severe first, without the evidence", async () => {
    const res = await t.as("francesco", { method: "GET", url: `/assessments/${aid}/findings` });
    expect(res.status).toBe(200);
    const body = res.json() as { items: Record<string, unknown>[]; total: number };
    expect(body.total).toBe(3);
    expect(body.items.map((f) => f["title"])).toEqual(["Any user can read any basket", "CSP header missing", "Open port 22"]);
    expect(body.items[0]).not.toHaveProperty("evidence");
    expect(body.items[0]).toHaveProperty("evidenceCount", 0);
  });

  it("filters by severity, phase, asset, owasp category and text, each narrowing the list", async () => {
    const titles = async (qs: string) => ((await t.as("francesco", { method: "GET", url: `/assessments/${aid}/findings?${qs}` })).json() as { items: { title: string }[] }).items.map((f) => f.title);
    expect(await titles("severity=high,medium")).toEqual(["Any user can read any basket", "CSP header missing"]);
    expect(await titles("phase=recon")).toEqual(["Open port 22"]);
    expect(await titles(`assetId=${box}`)).toEqual(["Open port 22"]);
    expect(await titles("owasp=A05")).toEqual(["CSP header missing"]);
    expect(await titles("owasp=A01,A05")).toHaveLength(2);
    expect(await titles("tool=manual")).toHaveLength(3);
    expect(await titles("tool=zap")).toEqual([]);
    expect(await titles("q=basket")).toEqual(["Any user can read any basket"]);
    expect(await titles("q=tcp/")).toEqual(["Open port 22"]);
    expect(await titles("status=closed")).toEqual([]);
    expect(await titles("severity=high&phase=recon")).toEqual([]);
  });

  it("pages with limit and offset and reports the total", async () => {
    const res = await t.as("francesco", { method: "GET", url: `/assessments/${aid}/findings?limit=2&offset=1` });
    const body = res.json() as { items: { title: string }[]; total: number; limit: number; offset: number };
    expect(body.items.map((f) => f.title)).toEqual(["CSP header missing", "Open port 22"]);
    expect(body).toMatchObject({ total: 3, limit: 2, offset: 1 });
  });

  it("refuses a filter value it does not know", async () => {
    const res = await t.as("francesco", { method: "GET", url: `/assessments/${aid}/findings?severity=urgent` });
    expect(res.status).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid query");
  });
});

describe("GET /findings/:id", () => {
  it("returns the finding with its evidence and its asset", async () => {
    const f = (await create()).json() as { id: string };
    await t.as("francesco", { method: "POST", url: `/findings/${f.id}/evidence`, body: { kind: "request-response", title: "Basket 2 as user 1", content: "GET /rest/basket/2 HTTP/1.1\r\n...\r\n\r\nHTTP/1.1 200 OK" } });
    const res = await t.as("francesco", { method: "GET", url: `/findings/${f.id}` });
    expect(res.status).toBe(200);
    const body = res.json() as { evidence: { title: string; redacted: boolean }[]; asset: { name: string } };
    expect(body.evidence).toHaveLength(1);
    expect(body.evidence[0]).toMatchObject({ title: "Basket 2 as user 1", redacted: false });
    expect(body.asset.name).toBe("Juice Shop");
  });

  it("is 404 for someone else, even with the right id", async () => {
    const f = (await create()).json() as { id: string };
    expect((await t.as("someone-else", { method: "GET", url: `/findings/${f.id}` })).status).toBe(404);
    expect((await t.as("root", { role: "admin", method: "GET", url: `/findings/${f.id}` })).status).toBe(200);
  });
});

describe("PATCH /findings/:id", () => {
  it("changes the written fields and the risk, keeps the schema's rules, bumps updatedAt", async () => {
    const f = (await create()).json() as { id: string; updatedAt: string };
    await new Promise((r) => setTimeout(r, 5));
    const res = await t.as("francesco", {
      method: "PATCH",
      url: `/findings/${f.id}`,
      body: { impact: "Reads any basket.", risk: { severity: "medium", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", baseScore: 6.5 } } },
    });
    expect(res.status).toBe(200);
    const g = res.json() as { impact: string; risk: { severity: string; cvss: { baseScore: number } }; updatedAt: string };
    expect(g.impact).toBe("Reads any basket.");
    expect(g.risk.cvss.baseScore).toBe(6.5);
    expect(g.updatedAt > f.updatedAt).toBe(true);
    const bad = await t.as("francesco", { method: "PATCH", url: `/findings/${f.id}`, body: { risk: { severity: "critical", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", baseScore: 6.5 } } } });
    expect(bad.status).toBe(400);
  });

  it("does not take the status, the phase, the retest or the sources here", async () => {
    const f = (await create()).json() as { id: string };
    const res = await t.as("francesco", { method: "PATCH", url: `/findings/${f.id}`, body: { status: "closed", phase: "risk", retest: { outcome: "fixed" }, sources: [] } });
    expect(res.status).toBe(400);
    expect((res.json() as { issues: { path: string }[] }).issues.map((i) => i.path).sort()).toEqual(["phase", "retest", "sources", "status"]);
  });

  it("can move the finding to another asset of the same assessment only", async () => {
    const f = (await create()).json() as { id: string };
    expect((await t.as("francesco", { method: "PATCH", url: `/findings/${f.id}`, body: { assetId: box } })).status).toBe(200);
    const other = await t.assessment("francesco");
    const elsewhere = ((await t.as("francesco", { method: "POST", url: `/assessments/${other}/assets`, body: { kind: "host", name: "x", host: "10.9.9.9" } })).json() as { id: string }).id;
    expect((await t.as("francesco", { method: "PATCH", url: `/findings/${f.id}`, body: { assetId: elsewhere } })).status).toBe(400);
  });
});

describe("POST /findings/:id/phase", () => {
  it("moves the finding and writes an audit line with the finding id and the reason", async () => {
    const f = (await create()).json() as { id: string };
    const res = await t.as("francesco", { method: "POST", url: `/findings/${f.id}/phase`, body: { phase: "risk", reason: "Reproduced with two accounts." } });
    expect(res.status).toBe(200);
    expect((res.json() as { phase: string }).phase).toBe("risk");
    const audit = (await t.as("francesco", { method: "GET", url: `/findings/${f.id}/audit` })).json() as { items: unknown[] };
    expect(audit.items).toEqual([expect.objectContaining({ findingId: f.id, action: "phase", from: "validation", to: "risk", reason: "Reproduced with two accounts.", actor: "francesco" })]);
    const all = (await t.as("francesco", { method: "GET", url: `/assessments/${aid}/audit` })).json() as { items: unknown[] };
    expect(all.items).toHaveLength(1);
  });

  it("writes nothing when the phase is already that", async () => {
    const f = (await create()).json() as { id: string };
    await t.as("francesco", { method: "POST", url: `/findings/${f.id}/phase`, body: { phase: "validation" } });
    expect(((await t.as("francesco", { method: "GET", url: `/findings/${f.id}/audit` })).json() as { items: unknown[] }).items).toEqual([]);
  });

  it("is 404 for someone else", async () => {
    const f = (await create()).json() as { id: string };
    expect((await t.as("someone-else", { method: "POST", url: `/findings/${f.id}/phase`, body: { phase: "risk" } })).status).toBe(404);
  });
});

describe("POST /findings/:id/evidence", () => {
  it("takes JSON evidence and returns it with an id", async () => {
    const f = (await create()).json() as { id: string };
    const res = await t.as("francesco", { method: "POST", url: `/findings/${f.id}/evidence`, body: { kind: "note", content: "Checked with user 1 and user 2.", redacted: true, capturedAt: "2026-11-09T18:30:00Z" } });
    expect(res.status).toBe(201);
    expect(res.json()).toMatchObject({ id: expect.stringMatching(/^ev-[0-9a-f]{12}$/), findingId: f.id, kind: "note", redacted: true, capturedAt: "2026-11-09T18:30:00.000Z" });
  });

  it("takes a plain-text body as the content, with the kind and the title from the query", async () => {
    const f = (await create()).json() as { id: string };
    const res = await t.as("francesco", {
      method: "POST",
      url: `/findings/${f.id}/evidence?kind=command-output&title=curl`,
      headers: { "content-type": "text/plain" },
      payload: "$ curl -s http://127.0.0.1:3000/rest/basket/2 -H 'Authorization: Bearer …'\n{\"status\":\"success\"}",
    });
    expect(res.status).toBe(201);
    expect(res.json()).toMatchObject({ kind: "command-output", title: "curl", redacted: false });
    const detail = (await t.as("francesco", { method: "GET", url: `/findings/${f.id}` })).json() as { evidence: { content: string }[] };
    expect(detail.evidence[0]!.content).toContain("curl -s");
  });

  it("refuses empty evidence and an unknown kind", async () => {
    const f = (await create()).json() as { id: string };
    expect((await t.as("francesco", { method: "POST", url: `/findings/${f.id}/evidence`, body: { kind: "note", content: "" } })).status).toBe(400);
    expect((await t.as("francesco", { method: "POST", url: `/findings/${f.id}/evidence`, body: { kind: "video", content: "x" } })).status).toBe(400);
    expect((await t.as("francesco", { method: "POST", url: `/findings/${f.id}/evidence`, headers: { "content-type": "text/plain" }, payload: "" })).status).toBe(400);
  });

  it("marks evidence as redacted with PATCH /evidence/:id, through the owner check", async () => {
    const f = (await create()).json() as { id: string };
    const e = (await t.as("francesco", { method: "POST", url: `/findings/${f.id}/evidence`, body: { kind: "note", content: "token=abc" } })).json() as { id: string };
    expect((await t.as("someone-else", { method: "PATCH", url: `/evidence/${e.id}`, body: { redacted: true } })).status).toBe(404);
    const res = await t.as("francesco", { method: "PATCH", url: `/evidence/${e.id}`, body: { redacted: true, content: "token=[redacted]" } });
    expect(res.status).toBe(200);
    expect(res.json()).toMatchObject({ redacted: true, content: "token=[redacted]" });
  });
});
