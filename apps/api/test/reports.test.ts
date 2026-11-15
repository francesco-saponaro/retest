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
    expect(section).toContain("OWASP A02, A03, A06; ASVS V5, V6, V9; CIS 3, 16; CWE-20, CWE-327; CVE-2015-9235");
    expect(section).toContain("_Not verified: a scanner reported it and nobody has checked it yet._");
  });

  it("ends with the coverage matrix for OWASP Top 10 and ASVS", async () => {
    const text = (await get(`/assessments/${aid}/report.md`)).text;
    const cov = text.slice(text.indexOf("## Coverage"));
    expect(cov).toContain("Tools run: nuclei, zap, trivy.");
    expect(cov).toContain("| A04 Insecure Design | 0 | 0 | 0 | none | Not tested |");
    expect(cov, cov).toMatch(/\| A06 Vulnerable and Outdated Components \| \d+ \| \d+ \| 0 \| nuclei, zap, trivy \| Findings \|/);
    expect(cov).toContain("| V1 Architecture, Design and Threat Modeling | 0 | 0 | 0 | none | Not tested |");
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
    expect(text).toMatch(/## Top risks\n\n1\. \*\*CVE-2015-9235 in jsonwebtoken 0\.4\.0: Verification Bypass in jsonwebtoken\*\* \(critical, 9\.8, not verified\)/);
    expect(text).toContain("0 of 19 findings verified by a person");
    expect(text).toContain("2 high or critical findings are still a scanner's claim.");
  });

  it("has a trend from the imports and says which OWASP categories nobody tested", async () => {
    const text = (await get(`/assessments/${aid}/summary.md`)).text;
    expect(text).toMatch(/## Trend\n\n\| Day \| Found \| Closed \| Set aside \| Reopened \| Open at end of day \|\n\| --- [^\n]+\n\| \d{4}-\d{2}-\d{2} \| 19 \| 0 \| 0 \| 0 \| 19 \|/);
    expect(text).toContain("Not tested: A04 Insecure Design, A08 Software and Data Integrity Failures, A09 Security Logging and Monitoring Failures.");
    expect(text).toContain("## Severity and business risk");
  });

  it("moves a finding up the top risks once a person verifies it", async () => {
    const list = (await get(`/assessments/${aid}/findings?q=prometheus`)).json() as { items: { id: string; title: string }[] };
    const fid = list.items[0]!.id;
    await t.as("francesco", { method: "POST", url: `/findings/${fid}/evidence`, body: { kind: "request-response", title: "curl", content: "GET /metrics HTTP/1.1\n\nHTTP/1.1 200 OK", redacted: true } });
    const moved = await t.as("francesco", { method: "POST", url: `/findings/${fid}/phase`, body: { phase: "validation" } });
    expect(moved.status, moved.text).toBe(200);
    const text = (await get(`/assessments/${aid}/summary.md`)).text;
    // Medium 5.3 and verified, so it now sits above the medium 6.1 findings nobody has checked.
    expect(text).toContain(`3. **${list.items[0]!.title}** (medium, 5.3, verified)`);
    expect(text).toContain("4. **CVE-2016-1000237 in sanitize-html 1.4.2");
    expect(text).toContain("1 of 19 findings verified by a person");
  });
});

describe("GET /assessments/:id/report", () => {
  it("is the report model the markdown is rendered from", async () => {
    const res = await get(`/assessments/${aid}/report`);
    expect(res.status).toBe(200);
    const r = res.json() as { counts: { findings: number; verified: number }; groups: { findings: { verified: boolean }[] }[]; coverage: { toolsRun: string[]; owasp: { id: string; state: string }[]; asvs: unknown[] }; trend: unknown[] };
    expect(r.counts).toMatchObject({ findings: 19, verified: 0 });
    expect(r.groups.flatMap((g) => g.findings).every((f) => f.verified === false)).toBe(true);
    expect(r.coverage.toolsRun).toEqual(["nuclei", "zap", "trivy"]);
    expect(r.coverage.owasp.find((x) => x.id === "A04")!.state).toBe("not-tested");
    expect(r.coverage.asvs).toHaveLength(14);
    expect(r.trend).toHaveLength(1);
  });

  it("is 404 for someone else", async () => {
    expect((await get(`/assessments/${aid}/report`, "someone-else")).status).toBe(404);
  });
});
