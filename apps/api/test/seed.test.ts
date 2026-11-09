import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { seedLab } from "../src/seed.js";
import { testApp, type TestApp } from "./app.js";

let t: TestApp;

beforeAll(async () => {
  t = await testApp();
});

afterAll(async () => {
  await t.close();
});

describe("seedLab", () => {
  it("creates the lab assessment for a user and imports the six fixtures into it", async () => {
    const result = await seedLab(t.db, { ownerId: "francesco" });
    expect(result.assessmentId).toMatch(/^a-/);
    expect(result.imports.map((i) => [i.tool, i.created, i.merged])).toEqual([
      ["nmap", 4, 0],
      ["nuclei", 11, 0],
      ["zap", 3, 3],
      ["semgrep", 7, 0],
      ["trivy", 5, 1],
      ["prowler", 7, 0],
    ]);
    const a = (await t.as("francesco", { method: "GET", url: `/assessments/${result.assessmentId}` })).json() as { name: string; phase: string; status: string; scope: { targets: string[] }; totals: { findings: number; assets: number; bySeverity: Record<string, number> } };
    expect(a.name).toBe("Juice Shop lab");
    expect(a.phase).toBe("assessment");
    expect(a.status).toBe("active");
    expect(a.totals).toMatchObject({ findings: 37, assets: 5, bySeverity: { critical: 4, high: 7, medium: 11, low: 3, info: 12 } });
    const audit = (await t.as("francesco", { method: "GET", url: `/assessments/${result.assessmentId}/audit` })).json() as { items: { action: string }[] };
    expect(audit.items.map((l) => l.action)).toEqual(["status", "phase", "import", "import", "import", "import", "import", "import"]);
    const assets = (await t.as("francesco", { method: "GET", url: `/assessments/${result.assessmentId}/assets` })).json() as { items: { inScope: boolean }[] };
    expect(assets.items.every((x) => x.inScope)).toBe(true);
  });

  it("makes a second lab for the same user rather than touching the first", async () => {
    const again = await seedLab(t.db, { ownerId: "francesco" });
    const list = (await t.as("francesco", { method: "GET", url: "/assessments" })).json() as { items: { id: string }[] };
    expect(list.items).toHaveLength(2);
    expect(list.items[0]!.id).toBe(again.assessmentId);
  });
});
