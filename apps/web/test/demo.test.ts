import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { demoClient, type DemoClient } from "../src/api/demo.js";

/**
 * The demo is the API's own services over PostgreSQL in WebAssembly, seeded from the fixtures
 * the browser ships. The counts here are the same ones the API's seed test asserts.
 */
let client: DemoClient;

beforeAll(async () => {
  client = await demoClient();
});

afterAll(async () => {
  await client.close();
});

describe("demoClient", () => {
  it("is in demo mode and holds the two lab assessments, newest first", async () => {
    expect(client.mode).toBe("demo");
    const items = await client.listAssessments();
    expect(items.map((a) => [a.id, a.name, a.phase, a.status])).toEqual([
      ["a-juice-shop-lab", "Juice Shop lab", "assessment", "active"],
      ["a-lab-network", "Lab network", "recon", "active"],
    ]);
  });

  it("gives the Juice Shop lab the same totals the API seed produces", async () => {
    const [juice] = await client.listAssessments();
    const a = await client.getAssessment(juice!.id);
    expect(a.totals).toMatchObject({ findings: 37, assets: 5, bySeverity: { critical: 4, high: 7, medium: 11, low: 3, info: 12 } });
    expect(a.totals.byPhase.validation + a.totals.byPhase.risk + a.totals.byPhase.remediation).toBe(0);
    expect(await client.listAssets(juice!.id)).toHaveLength(5);
    const imports = await client.listImports(juice!.id);
    // Newest first, as the API lists them; the lab ran the tools in the opposite order.
    expect(imports.map((i) => [i.tool, i.created, i.merged])).toEqual([
      ["prowler", 7, 0],
      ["trivy", 5, 1],
      ["semgrep", 7, 0],
      ["zap", 3, 3],
      ["nuclei", 11, 0],
      ["nmap", 4, 0],
    ]);
    expect(imports.every((i) => new Date(i.at).getTime() < Date.now())).toBe(true);
    const audit = await client.listAudit(juice!.id);
    expect(audit.map((l) => l.action)).toEqual(["status", "phase", "import", "import", "import", "import", "import", "import"]);
  });

  it("gives the lab network its one host inside the authorised network", async () => {
    const [, lab] = await client.listAssessments();
    const a = await client.getAssessment(lab!.id);
    expect(a.scope.targets).toEqual(["10.0.10.0/24"]);
    expect(a.totals).toMatchObject({ findings: 6, assets: 1 });
    const assets = await client.listAssets(lab!.id);
    expect(assets).toEqual([expect.objectContaining({ host: "10.0.10.11", inScope: true })]);
    expect((await client.listImports(lab!.id)).map((i) => i.warnings)).toEqual([[]]);
  });

  it("answers a 404 for an assessment that is not there", async () => {
    await expect(client.getAssessment("a-000000000000")).rejects.toMatchObject({ status: 404 });
  });

  it("lists the lab's findings with the API's filters, most severe first", async () => {
    const all = await client.listFindings("a-juice-shop-lab", {});
    expect(all.total).toBe(37);
    expect(all.items).toHaveLength(37);
    expect(all.items[0]!.risk.severity).toBe("critical");
    expect(all.items.at(-1)!.risk.severity).toBe("info");
    expect((await client.listFindings("a-juice-shop-lab", { severity: "critical" })).total).toBe(4);
    expect((await client.listFindings("a-juice-shop-lab", { tool: "zap" })).total).toBe(6);
    expect((await client.listFindings("a-juice-shop-lab", { phase: "recon" })).total).toBe(4);
    expect((await client.listFindings("a-juice-shop-lab", { owasp: "A05" })).total).toBe(6);
    expect((await client.listFindings("a-juice-shop-lab", { q: "sanitize-html" })).items.map((f) => f.scope)).toEqual(["sanitize-html@1.4.2", "sanitize-html@1.4.2"]);
    await expect(client.listFindings("a-000000000000", {})).rejects.toMatchObject({ status: 404 });
  });

  it("reads one finding with its asset and its evidence, and a 404 for one that is not there", async () => {
    const { items } = await client.listFindings("a-juice-shop-lab", { tool: "nuclei", q: "CORS" });
    const f = await client.getFinding(items[0]!.id);
    expect(f.title).toBe("CORS Misconfiguration: arbitrary-origin");
    expect(f.asset).toMatchObject({ kind: "web-app", url: "http://127.0.0.1:3000" });
    expect(f.sources.map((s) => s.tool)).toEqual(["nuclei", "zap"]);
    expect(f.evidence).toHaveLength(2);
    expect(f.evidence[0]!.kind).toBe("request-response");
    await expect(client.getFinding("f-000000000000")).rejects.toMatchObject({ status: 404, message: "finding not found" });
  });

  it("stores a CVSS vector as the finding's risk and the totals follow", async () => {
    const { items } = await client.listFindings("a-juice-shop-lab", { q: "CORS" });
    const before = await client.getAssessment("a-juice-shop-lab");
    const risk = { severity: "high" as const, cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", baseScore: 7.5 } };
    const updated = await client.updateFinding(items[0]!.id, { risk });
    expect(updated.risk).toEqual(risk);
    const after = await client.getAssessment("a-juice-shop-lab");
    expect(after.totals.bySeverity.high).toBe(before.totals.bySeverity.high + 1);
    expect(after.totals.bySeverity.medium).toBe(before.totals.bySeverity.medium - 1);
    await expect(client.updateFinding(items[0]!.id, { risk: { severity: "low", cvss: risk.cvss } })).rejects.toMatchObject({ status: 400 });
  });
});
