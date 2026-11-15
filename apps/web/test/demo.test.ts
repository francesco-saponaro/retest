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
    // The imports leave everything in recon or assessment; the three verified ones are the walk-through's, below.
    expect(a.totals.byPhase.validation + a.totals.byPhase.risk + a.totals.byPhase.remediation).toBe(3);
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
    expect(audit.slice(0, 8).map((l) => l.action)).toEqual(["status", "phase", "import", "import", "import", "import", "import", "import"]);
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
    expect(f.evidence).toHaveLength(3);
    expect(f.evidence.map((e) => e.kind).sort()).toEqual(["command-output", "request-response", "scanner-output"]);
    expect(f.evidence.filter((e) => e.source).map((e) => e.source!.tool)).toEqual(["nuclei", "zap"]);
    await expect(client.getFinding("f-000000000000")).rejects.toMatchObject({ status: 404, message: "finding not found" });
  });

  it("stores a CVSS vector as the finding's risk and the totals follow", async () => {
    const { items } = await client.listFindings("a-juice-shop-lab", { q: "content-security-policy" });
    const before = await client.getAssessment("a-juice-shop-lab");
    const risk = { severity: "high" as const, cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", baseScore: 7.5 } };
    const updated = await client.updateFinding(items[0]!.id, { risk });
    expect(updated.risk).toEqual(risk);
    const after = await client.getAssessment("a-juice-shop-lab");
    expect(after.totals.bySeverity.high).toBe(before.totals.bySeverity.high + 1);
    expect(after.totals.bySeverity.medium).toBe(before.totals.bySeverity.medium - 1);
    await expect(client.updateFinding(items[0]!.id, { risk: { severity: "low", cvss: risk.cvss } })).rejects.toMatchObject({ status: 400 });
  });

  it("has walked three findings through the workflow, so the lab shows every state of it", async () => {
    const a = await client.getAssessment("a-juice-shop-lab");
    expect(a.totals.byPhase).toMatchObject({ recon: 4, assessment: 30, validation: 1, risk: 1, remediation: 1 });
    expect(a.totals.byStatus).toMatchObject({ open: 36, "false-positive": 1, "accepted-risk": 0, closed: 0 });
    const cors = await client.getFinding("f-9c67368df231");
    expect(cors.phase).toBe("risk");
    expect(cors.evidence.filter((e) => !e.source)).toHaveLength(1);
    expect(cors.risk).toEqual({ severity: "medium", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", baseScore: 5.3 } });
    const timestamp = await client.getFinding("f-83eaab78bf12");
    expect(timestamp).toMatchObject({ status: "false-positive", phase: "validation" });
    expect(timestamp.falsePositiveReason).toMatch(/main\.js/);
    const jwt = await client.getFinding("f-7f910fa0b432");
    expect(jwt).toMatchObject({ phase: "remediation", status: "open", retest: { outcome: "not-fixed" } });
    expect(jwt.risk.cvss?.baseScore).toBe(9.8);
    const history = await client.listAudit("a-juice-shop-lab");
    expect(history).toHaveLength(16);
    expect((await client.listFindingAudit("f-7f910fa0b432")).map((l) => [l.action, l.to])).toEqual([
      ["phase", "validation"],
      ["phase", "risk"],
      ["phase", "remediation"],
      ["retest", "not-fixed"],
    ]);
  });

  it("writes the report in the browser from the same model as the API, with the lab's two verified findings first", async () => {
    const r = await client.getReport("a-juice-shop-lab");
    expect(r.counts).toMatchObject({ findings: 37, verified: 2, falsePositive: 1 });
    expect(r.coverage.toolsRun).toEqual(["nmap", "nuclei", "zap", "semgrep", "trivy", "prowler"]);
    expect(r.topRisks[0]).toMatchObject({ id: "f-7f910fa0b432", verified: true });
    // No tool sets out to test design, but a finding whose CWE belongs to A04 still lands there.
    expect(r.coverage.owasp.find((x) => x.id === "A04")).toMatchObject({ state: "found", lookedBy: [] });
    const summary = await client.getReportMarkdown("a-juice-shop-lab", "summary");
    expect(summary).toMatch(/^# Juice Shop lab[^\n]*: executive summary/);
    expect(summary).toContain("2 of 37 findings verified by a person");
    expect(await client.getReportMarkdown("a-juice-shop-lab", "report")).toContain("## Coverage");
    await expect(client.getReport("nope")).rejects.toMatchObject({ status: 404 });
  });

  it("runs the workflow rules in the browser: the same refusals as the API, in the same words", async () => {
    const { items } = await client.listFindings("a-juice-shop-lab", { q: "Prometheus" });
    const fid = items[0]!.id;
    await expect(client.setFindingPhase(fid, { phase: "validation" })).rejects.toMatchObject({ status: 409, message: /evidence captured by a person/ });
    await client.addEvidence(fid, { kind: "command-output", title: "curl /metrics", content: "$ curl -s http://127.0.0.1:3000/metrics | head -3\n# HELP process_cpu_user_seconds_total …", redacted: true });
    const moved = await client.setFindingPhase(fid, { phase: "validation", reason: "The endpoint answers without a token." });
    expect(moved.phase).toBe("validation");
    await expect(client.setFindingStatus(fid, { status: "closed" })).rejects.toMatchObject({ status: 409, message: /retest/ });
    await expect(client.recordRetest(fid, { outcome: "fixed", notes: "x" })).rejects.toMatchObject({ status: 409, message: /validation/ });
    const fp = await client.setFindingStatus(fid, { status: "false-positive", reason: "Metrics are meant to be public in the lab." });
    expect(fp).toMatchObject({ status: "false-positive", falsePositiveReason: "Metrics are meant to be public in the lab." });
    expect((await client.listFindingAudit(fid)).map((l) => l.action)).toEqual(["phase", "status"]);
    const totals = (await client.getAssessment("a-juice-shop-lab")).totals;
    expect(totals.byStatus["false-positive"]).toBe(2);
  });

  it("closes a finding through a retest that found it fixed", async () => {
    const closed = await client.recordRetest("f-7f910fa0b432", { outcome: "fixed", notes: "jsonwebtoken 9.0.2 in the image; a token signed HS256 with the public key is refused with JsonWebTokenError." });
    expect(closed.status).toBe("closed");
    expect(closed.retest?.outcome).toBe("fixed");
    await expect(client.updateFinding("f-7f910fa0b432", { impact: "x" })).rejects.toMatchObject({ status: 409 });
    expect((await client.getAssessment("a-juice-shop-lab")).totals.byStatus.closed).toBe(1);
    const reopened = await client.setFindingStatus("f-7f910fa0b432", { status: "open", reason: "Regressed." });
    expect(reopened.status).toBe("open");
  });

  it("marks a piece of evidence redacted", async () => {
    const f = await client.getFinding("f-9c67368df231");
    const piece = f.evidence.find((e) => e.source)!;
    expect(piece.redacted).toBe(false);
    const updated = await client.updateEvidence(piece.id, { redacted: true });
    expect(updated.redacted).toBe(true);
    await expect(client.updateEvidence("ev-000000000000", { redacted: true })).rejects.toMatchObject({ status: 404 });
  });
});
