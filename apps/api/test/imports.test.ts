import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { testApp, type TestApp } from "./app.js";
import { fixture } from "./helpers.js";

let t: TestApp;
let aid: string;

beforeAll(async () => {
  t = await testApp();
});

afterAll(async () => {
  await t.close();
});

beforeEach(async () => {
  await t.reset();
  aid = await t.assessment("francesco", { scope: { targets: ["127.0.0.1", "http://127.0.0.1:3000", "juice-shop", "bkimminich/juice-shop:v17.1.1", "aws 123456789012"], authorizedBy: "me" } });
});

interface ImportResult {
  id: string;
  tool: string;
  parsed: number;
  created: number;
  merged: number;
  assetsCreated: number;
  warnings: string[];
  unmapped: { cwe: number[]; checks: string[] };
  notes: string[];
}

async function importFile(tool: string, file: string, extra: Record<string, unknown> = {}, sub = "francesco", assessmentId = aid) {
  return t.as(sub, { method: "POST", url: "/imports", body: { assessmentId, tool, filename: file, content: fixture(file), ...extra } });
}

async function totals(id = aid) {
  return ((await t.as("francesco", { method: "GET", url: `/assessments/${id}` })).json() as { totals: { findings: number; assets: number; bySeverity: Record<string, number> } }).totals;
}

describe("POST /imports", () => {
  it("imports an Nmap file as JSON: four findings on one host, with the counts", async () => {
    const res = await importFile("nmap", "nmap/juice-shop.xml");
    expect(res.status).toBe(201);
    const r = res.json() as ImportResult;
    expect(r).toMatchObject({ id: expect.stringMatching(/^imp-[0-9a-f]{12}$/), tool: "nmap", parsed: 4, created: 4, merged: 0, assetsCreated: 1, warnings: [], unmapped: { cwe: [], checks: [] }, notes: [] });
    expect(await totals()).toMatchObject({ findings: 4, assets: 1, bySeverity: { info: 4 } });
    const assets = (await t.as("francesco", { method: "GET", url: `/assessments/${aid}/assets` })).json() as { items: { id: string; kind: string; inScope: boolean }[] };
    expect(assets.items).toEqual([expect.objectContaining({ id: "asset-host-127-0-0-1", kind: "host", inScope: true })]);
  });

  it("takes the file as a raw body with the tool and the assessment in the query", async () => {
    const res = await t.as("francesco", {
      method: "POST",
      url: `/imports?assessmentId=${aid}&tool=nuclei&filename=juice.jsonl`,
      headers: { "content-type": "application/x-ndjson" },
      payload: fixture("nuclei/juice-shop.jsonl"),
    });
    expect(res.status).toBe(201);
    expect(res.json()).toMatchObject({ tool: "nuclei", parsed: 11, created: 11, assetsCreated: 1 });
  });

  it("imports the same file twice without making anything twice", async () => {
    await importFile("nmap", "nmap/juice-shop.xml");
    const again = (await importFile("nmap", "nmap/juice-shop.xml")).json() as ImportResult;
    expect(again).toMatchObject({ parsed: 4, created: 0, merged: 4, assetsCreated: 0 });
    expect(await totals()).toMatchObject({ findings: 4, assets: 1 });
    const list = (await t.as("francesco", { method: "GET", url: `/assessments/${aid}/findings` })).json() as { items: { sources: unknown[]; evidenceCount: number }[] };
    expect(list.items.every((f) => f.sources.length === 1)).toBe(true);
    expect(list.items.map((f) => f.evidenceCount).sort()).toEqual([1, 2, 3, 5]);
  });

  it("folds a ZAP report into the findings Nuclei already made on the same site", async () => {
    await importFile("nuclei", "nuclei/juice-shop.jsonl");
    const zap = (await importFile("zap", "zap/juice-shop.json")).json() as ImportResult;
    expect(zap).toMatchObject({ parsed: 6, created: 3, merged: 3, assetsCreated: 0 });
    expect(await totals()).toMatchObject({ findings: 14, assets: 1 });
    const csp = ((await t.as("francesco", { method: "GET", url: `/assessments/${aid}/findings?q=content-security` })).json() as { items: { sources: { tool: string; rawId: string }[]; risk: { severity: string }; mappings: { owaspTop10: string[] } }[] }).items;
    expect(csp).toHaveLength(1);
    expect(csp[0]!.sources.map((s) => `${s.tool}:${s.rawId}`)).toEqual(["nuclei:http-missing-security-headers:content-security-policy", "zap:10038"]);
    expect(csp[0]!.risk.severity).toBe("medium");
    expect(csp[0]!.mappings.owaspTop10).toEqual(["A05"]);
  });

  it("needs the repository name for Semgrep, and puts the results on it", async () => {
    const missing = await importFile("semgrep", "semgrep/juice-shop.sarif");
    expect(missing.status).toBe(400);
    expect((missing.json() as { issues: { path: string }[] }).issues.map((i) => i.path)).toEqual(["repository"]);
    const res = (await importFile("semgrep", "semgrep/juice-shop.sarif", { repository: "juice-shop" })).json() as ImportResult;
    expect(res).toMatchObject({ parsed: 7, created: 7, assetsCreated: 1 });
    const assets = (await t.as("francesco", { method: "GET", url: `/assessments/${aid}/assets` })).json() as { items: { kind: string; name: string }[] };
    expect(assets.items).toEqual([expect.objectContaining({ kind: "repository", name: "juice-shop" })]);
  });

  it("puts a Trivy report on the image it is told, when the report only names a saved copy", async () => {
    const report = JSON.parse(fixture("trivy/juice-shop-image.json")) as Record<string, unknown>;
    report.ArtifactName = "/out/juice-shop-image.tar";
    const res = await t.as("francesco", {
      method: "POST",
      url: "/imports",
      body: { assessmentId: aid, tool: "trivy", content: JSON.stringify(report), image: "bkimminich/juice-shop:v17.1.1" },
    });
    expect(res.status).toBe(201);
    const assets = (await t.as("francesco", { method: "GET", url: `/assessments/${aid}/assets` })).json() as { items: { kind: string; name: string }[] };
    expect(assets.items.map((a) => a.name)).toEqual(["bkimminich/juice-shop:v17.1.1"]);
  });

  it("keeps the parser's warnings and the classifier's notes", async () => {
    const damaged = (await importFile("nuclei", "nuclei/damaged.jsonl")).json() as ImportResult;
    expect(damaged.created).toBe(1);
    expect(damaged.warnings).toEqual(["line 2: not JSON", "line 4: template-id: Invalid input: expected string, received undefined"]);
    const vms = (await importFile("nmap", "nmap/lab-vms.xml")).json() as ImportResult;
    expect(vms.notes).toHaveLength(2);
    expect(vms.notes[0]).toMatch(/bare score 9.8/);
  });

  it("marks an asset outside the authorised scope and says so", async () => {
    const vms = (await importFile("nmap", "nmap/lab-vms.xml")).json() as ImportResult;
    expect(vms.warnings).toEqual(["asset lab-linux (10.0.10.11) is not covered by the scope: it was recorded as out of scope"]);
    const assets = (await t.as("francesco", { method: "GET", url: `/assessments/${aid}/assets` })).json() as { items: { host: string; inScope: boolean }[] };
    expect(assets.items).toEqual([expect.objectContaining({ host: "10.0.10.11", inScope: false })]);
  });

  it("treats a network in the scope as covering its hosts", async () => {
    const id = await t.assessment("francesco", { scope: { targets: ["10.0.10.0/24"], authorizedBy: "me" } });
    const vms = (await importFile("nmap", "nmap/lab-vms.xml", {}, "francesco", id)).json() as ImportResult;
    expect(vms.warnings).toEqual([]);
  });

  it("refuses a tool it cannot parse, a file it cannot parse, and a body with no content", async () => {
    expect((await importFile("manual", "nmap/juice-shop.xml")).status).toBe(400);
    expect((await importFile("openvas", "nmap/juice-shop.xml")).status).toBe(400);
    const broken = await t.as("francesco", { method: "POST", url: "/imports", body: { assessmentId: aid, tool: "zap", content: "<html>not json" } });
    expect(broken.status).toBe(400);
    expect((broken.json() as { error: string }).error).toMatch(/could not parse/);
    expect((await t.as("francesco", { method: "POST", url: "/imports", body: { assessmentId: aid, tool: "nmap", content: "" } })).status).toBe(400);
  });

  it("is 404 on someone else's assessment and 409 on a closed one", async () => {
    expect((await importFile("nmap", "nmap/juice-shop.xml", {}, "someone-else")).status).toBe(404);
    await t.as("francesco", { method: "POST", url: `/assessments/${aid}/status`, body: { status: "closed" } });
    expect((await importFile("nmap", "nmap/juice-shop.xml")).status).toBe(409);
  });

  it("writes an audit line and a row in the imports table", async () => {
    await importFile("trivy", "trivy/juice-shop-image.json");
    const audit = (await t.as("francesco", { method: "GET", url: `/assessments/${aid}/audit` })).json() as { items: { action: string; field: string; to: string }[] };
    expect(audit.items).toEqual([expect.objectContaining({ action: "import", field: "trivy", to: "6 parsed, 5 created, 1 merged" })]);
    const imports = (await t.as("francesco", { method: "GET", url: `/assessments/${aid}/imports` })).json() as { items: { tool: string; filename: string; created: number }[] };
    expect(imports.items).toEqual([expect.objectContaining({ tool: "trivy", filename: "trivy/juice-shop-image.json", created: 5 })]);
  });

  it("runs the whole lab through the API with the same counts as the pipeline", async () => {
    const runs: [string, string, Record<string, unknown>][] = [
      ["nmap", "nmap/juice-shop.xml", {}],
      ["nuclei", "nuclei/juice-shop.jsonl", {}],
      ["zap", "zap/juice-shop.json", {}],
      ["semgrep", "semgrep/juice-shop.sarif", { repository: "juice-shop" }],
      ["trivy", "trivy/juice-shop-image.json", {}],
      ["prowler", "prowler/lab-account.ocsf.json", {}],
    ];
    let created = 0;
    for (const [tool, file, extra] of runs) {
      const r = (await importFile(tool, file, extra)).json() as ImportResult;
      expect(r.warnings.filter((w) => w.includes("not covered"))).toEqual([]);
      created += r.created;
    }
    expect(created).toBe(37);
    expect(await totals()).toMatchObject({ findings: 37, assets: 5, bySeverity: { critical: 4, high: 7, medium: 11, low: 3, info: 12 } });
    const withCvss = (await t.as("francesco", { method: "GET", url: `/assessments/${aid}/findings?limit=500` })).json() as { items: { risk: { cvss?: unknown } }[] };
    expect(withCvss.items.filter((f) => f.risk.cvss).length).toBe(6);
  });
});
