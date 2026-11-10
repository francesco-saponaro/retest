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
});
