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
  aid = await t.assessment("francesco", { name: "Juice Shop lab", client: "Me", scope: { targets: ["127.0.0.1", "http://127.0.0.1:3000", "juice-shop", "bkimminich/juice-shop:v17.1.1", "123456789012"], authorizedBy: "me", authorizedAt: "2026-11-09T18:00:00Z" } });
  for (const [tool, file, extra] of [
    ["nuclei", "nuclei/juice-shop.jsonl", {}],
    ["zap", "zap/juice-shop.json", {}],
    ["trivy", "trivy/juice-shop-image.json", {}],
  ] as const) {
    await t.as("francesco", { method: "POST", url: "/imports", body: { assessmentId: aid, tool, content: fixture(file), ...extra } });
  }
});

async function get(path: string, sub = "francesco") {
  return t.as(sub, { method: "GET", url: path });
}

describe("GET /assessments/:id/report.md", () => {
  it("is markdown, grouped by asset, one section per finding with the seven fields in order", async () => {
    const res = await get(`/assessments/${aid}/report.md`);
    expect(res.status).toBe(200);
    expect(res.text.startsWith("# Juice Shop lab")).toBe(true);
    const text = res.text;
    expect(text).toContain("## 127.0.0.1:3000 (http://127.0.0.1:3000)");
    expect(text).toContain("## bkimminich/juice-shop:v17.1.1");
    expect(text.indexOf("## 127.0.0.1:3000")).toBeLessThan(text.indexOf("## bkimminich/juice-shop:v17.1.1"));
    const section = text.slice(text.indexOf("### CVE-2015-9235 in jsonwebtoken 0.4.0"));
    const order = ["**Asset and scope:**", "**Impact:**", "**Evidence:**", "**Risk:**", "**Fix:**", "**Retest:**"].map((h) => section.indexOf(h));
    expect(order.every((i) => i >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(section).toContain("critical, CVSS 9.8 (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)");
    expect(section).toContain("OWASP A02, A03; ASVS V5, V6, V9; CIS 3, 16; CWE-20, CWE-327; CVE-2015-9235");
  });

  it("orders the findings in a section by severity and prints every source", async () => {
    const text = (await get(`/assessments/${aid}/report.md`)).text;
    const web = text.slice(text.indexOf("## 127.0.0.1:3000"), text.indexOf("## bkimminich"));
    const titles = [...web.matchAll(/^### (.+)$/gm)].map((m) => m[1]);
    expect(titles.slice(0, 3).every((x) => /Prometheus|content-security-policy|CORS/.test(x!))).toBe(true);
    expect(titles[titles.length - 1]).toMatch(/Wappalyzer|robots|Swagger|Missing Security Headers|Suspicious/);
    expect(web).toContain("Sources: nuclei http-missing-security-headers:content-security-policy, zap 10038");
  });

  it("prints only redacted evidence, and says how many pieces were held back", async () => {
    const text = (await get(`/assessments/${aid}/report.md`)).text;
    expect(text).not.toContain("HTTP/1.1 200 OK");
    expect(text).toMatch(/\d+ pieces? of evidence not yet redacted/);
    const list = (await get(`/assessments/${aid}/findings?q=prometheus`)).json() as { items: { id: string }[] };
    const detail = (await get(`/findings/${list.items[0]!.id}`)).json() as { evidence: { id: string }[] };
    await t.as("francesco", { method: "PATCH", url: `/evidence/${detail.evidence[0]!.id}`, body: { redacted: true } });
    const after = (await get(`/assessments/${aid}/report.md`)).text;
    expect(after).toContain("```\nGET /metrics HTTP/1.1");
  });

  it("is 404 for someone else", async () => {
    expect((await get(`/assessments/${aid}/report.md`, "someone-else")).status).toBe(404);
  });
});

describe("GET /assessments/:id/summary.md", () => {
  it("has the totals, the top risks and the phase of the work", async () => {
    const res = await get(`/assessments/${aid}/summary.md`);
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/^text\/markdown/);
    const text = res.text;
    expect(text).toContain("# Juice Shop lab: executive summary");
    expect(text).toContain("| Critical | 2 |");
    expect(text).toContain("| High | 0 |");
    expect(text).toContain("| Medium | 6 |");
    expect(text).toContain("| Low | 3 |");
    expect(text).toContain("| Informational | 8 |");
    expect(text).toContain("19 findings on 2 assets");
    expect(text).toContain("Phase: 1 of 6, Scope and asset inventory");
    expect(text).toMatch(/## Top risks\n\n1\. \*\*CVE-2015-9235 in jsonwebtoken 0\.4\.0: Verification Bypass in jsonwebtoken\*\* \(critical, 9\.8\)/);
    expect(text).toContain("0 of 19 findings validated");
  });
});
