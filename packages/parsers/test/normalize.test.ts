import { AssetSchema, FindingSchema } from "@retest/schema";
import { describe, expect, it } from "vitest";
import { parseNmap } from "../src/nmap.js";
import { UNASSESSED_IMPACT, UNWRITTEN_FIX, normalize } from "../src/normalize.js";
import { parseNuclei } from "../src/nuclei.js";
import { parseProwler } from "../src/prowler.js";
import { parseSemgrep } from "../src/semgrep.js";
import { parseTrivy } from "../src/trivy.js";
import type { RawFinding } from "../src/raw.js";
import { fixture } from "./helpers.js";

const now = new Date("2026-11-07T19:00:00Z");
const nmapRaw = parseNmap(fixture("nmap/juice-shop.xml")).findings;
const nmapLabRaw = parseNmap(fixture("nmap/lab-vms.xml")).findings;
const nucleiRaw = parseNuclei(fixture("nuclei/juice-shop.jsonl")).findings;

describe("normalize: Nmap output", () => {
  const { findings, assets } = normalize(nmapRaw, { assessmentId: "lab", now });

  it("makes one host asset for the scanned address", () => {
    expect(assets).toHaveLength(1);
    expect(assets[0]).toEqual({
      id: "asset-host-127-0-0-1",
      assessmentId: "lab",
      kind: "host",
      name: "localhost",
      host: "127.0.0.1",
      inScope: true,
      tags: [],
    });
    expect(AssetSchema.safeParse(assets[0]).success).toBe(true);
  });

  it("makes one finding per raw finding, each one valid against the schema", () => {
    expect(findings).toHaveLength(4);
    for (const f of findings) {
      const parsed = FindingSchema.safeParse(f);
      expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
    }
  });

  it("fills the seven fields: what the tool knows, and an honest placeholder for what it does not", () => {
    const web = findings[1]!;
    expect(web.title).toBe("http on tcp/3000 (Node.js Express framework)");
    expect(web.assetId).toBe("asset-host-127-0-0-1");
    expect(web.scope).toBe("tcp/3000");
    expect(web.impact).toBe(UNASSESSED_IMPACT);
    expect(web.fix).toBe(UNWRITTEN_FIX);
    expect(web.risk).toEqual({ severity: "info" });
    expect(web.retest).toBeUndefined();
  });

  it("puts a port inventory finding in the recon phase, open, with its source", () => {
    const web = findings[1]!;
    expect(web.phase).toBe("recon");
    expect(web.status).toBe("open");
    expect(web.sources).toEqual([{ tool: "nmap", rawId: "tcp/3000" }]);
    expect(web.mappings).toEqual({ cwe: [], cve: [], owaspTop10: [], owaspApi: [], asvs: [], cis: [] });
    expect(web.createdAt).toBe("2026-11-07T19:00:00.000Z");
    expect(web.updatedAt).toBe("2026-11-07T19:00:00.000Z");
  });

  it("turns each evidence block into an Evidence record, not yet redacted, stamped with its source", () => {
    const web = findings[1]!;
    expect(web.evidence).toHaveLength(5);
    expect(web.evidence[0]).toEqual({
      id: `${web.id}-e1`,
      findingId: web.id,
      kind: "scanner-output",
      title: "nmap -sV -sC -p- -oX fixtures/nmap/juice-shop.xml 127.0.0.1",
      content: "3000/tcp open  http  Node.js Express framework",
      redacted: false,
      capturedAt: "2026-11-07T17:02:11.000Z",
      source: { tool: "nmap", rawId: "tcp/3000" },
    });
    expect(web.evidence[1]!.kind).toBe("command-output");
    expect(web.evidence[1]!.id).toBe(`${web.id}-e2`);
  });

  it("gives the same input the same ids every time", () => {
    const again = normalize(nmapRaw, { assessmentId: "lab", now: new Date() });
    expect(again.findings.map((f) => f.id)).toEqual(findings.map((f) => f.id));
    expect(findings[0]!.id).toMatch(/^f-[0-9a-f]{12}$/);
    expect(new Set(findings.map((f) => f.id)).size).toBe(4);
  });

  it("gives a different assessment different ids", () => {
    const other = normalize(nmapRaw, { assessmentId: "other", now });
    expect(other.findings[0]!.id).not.toBe(findings[0]!.id);
  });
});

describe("normalize: Nuclei output", () => {
  const { findings, assets } = normalize(nucleiRaw, { assessmentId: "lab", now });

  it("makes one web app asset per origin", () => {
    expect(assets).toEqual([
      {
        id: "asset-web-127-0-0-1-3000",
        assessmentId: "lab",
        kind: "web-app",
        name: "127.0.0.1:3000",
        host: "127.0.0.1",
        port: 3000,
        url: "http://127.0.0.1:3000",
        inScope: true,
        tags: [],
      },
    ]);
  });

  it("keeps the tool's severity, CWE and remediation, and leaves CVSS and the standards for classify()", () => {
    expect(findings).toHaveLength(11);
    for (const f of findings) expect(FindingSchema.safeParse(f).success).toBe(true);
    const metrics = findings.find((f) => f.sources[0]!.rawId === "prometheus-metrics")!;
    expect(metrics.phase).toBe("assessment");
    expect(metrics.risk).toEqual({ severity: "medium" });
    expect(metrics.fix).toBe("Restrict access to the metrics endpoint or move it to an internal listener.");
    expect(metrics.impact).toBe(UNASSESSED_IMPACT);
    expect(metrics.mappings).toEqual({ cwe: [200], cve: [], owaspTop10: [], owaspApi: [], asvs: [], cis: [] });
    expect(metrics.scope).toBe("GET /metrics");
    expect(metrics.assetId).toBe("asset-web-127-0-0-1-3000");
  });

  it("links the source to the template page and keeps the tool's own rating on it", () => {
    const cors = findings.find((f) => f.sources[0]!.rawId === "cors-misconfig:arbitrary-origin")!;
    expect(cors.sources).toEqual([
      {
        tool: "nuclei",
        rawId: "cors-misconfig:arbitrary-origin",
        reference: "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/generic/cors-misconfig.yaml",
        severity: "low",
      },
    ]);
    expect(cors.risk.severity).toBe("low");
    const metrics = findings.find((f) => f.sources[0]!.rawId === "prometheus-metrics")!;
    expect(metrics.sources[0]!.severity).toBe("medium");
    expect(metrics.sources[0]!.cvss).toEqual({ vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 5.3 });
    // The finding's own risk still has no CVSS: the vector is the tool's claim until classify() checks it.
    expect(metrics.risk.cvss).toBeUndefined();
  });

  it("keeps the request and response as evidence, captured when the tool says", () => {
    const robots = findings.find((f) => f.sources[0]!.rawId === "robots-txt-endpoint")!;
    expect(robots.evidence).toHaveLength(2);
    expect(robots.evidence[0]!.kind).toBe("request-response");
    expect(robots.evidence[0]!.capturedAt).toBe("2026-11-07T18:12:41.402117+01:00");
    expect(robots.evidence[0]!.redacted).toBe(false);
  });
});

describe("normalize: several tools and several runs", () => {
  it("reuses an asset it is given instead of making a second one", () => {
    const first = normalize(nmapRaw, { assessmentId: "lab", now });
    const second = normalize(nmapRaw, { assessmentId: "lab", now, assets: first.assets });
    expect(second.assets).toHaveLength(1);
    expect(second.assets[0]).toBe(first.assets[0]);
    expect(second.findings[0]!.assetId).toBe(first.assets[0]!.id);
  });

  it("matches a given asset by what it is, not by its id", () => {
    const existing = AssetSchema.parse({
      id: "juice-shop",
      assessmentId: "lab",
      kind: "web-app",
      name: "Juice Shop",
      url: "http://127.0.0.1:3000",
    });
    const { findings, assets } = normalize(nucleiRaw, { assessmentId: "lab", now, assets: [existing] });
    expect(assets).toEqual([existing]);
    expect(findings.every((f) => f.assetId === "juice-shop")).toBe(true);
  });

  it("keeps a host and the web app on it as two assets", () => {
    const { findings, assets } = normalize([...nmapRaw, ...nucleiRaw], { assessmentId: "lab", now });
    expect(assets.map((a) => a.id)).toEqual(["asset-host-127-0-0-1", "asset-web-127-0-0-1-3000"]);
    expect(findings).toHaveLength(15);
    expect(new Set(findings.map((f) => f.id)).size).toBe(15);
  });

  it("makes one host asset per address and nothing for a host that was down", () => {
    const { findings, assets } = normalize(nmapLabRaw, { assessmentId: "lab", now });
    expect(assets.map((a) => a.id)).toEqual(["asset-host-10-0-10-11"]);
    expect(assets[0]!.name).toBe("lab-linux");
    expect(findings).toHaveLength(6);
    const vulners = findings.find((f) => f.sources[0]!.rawId === "tcp/80/vulners")!;
    expect(vulners.phase).toBe("assessment");
    expect(vulners.risk).toEqual({ severity: "info" });
    expect(vulners.impact).not.toBe(UNASSESSED_IMPACT);
    expect(vulners.sources[0]!.reference).toBe("https://vulners.com/cve/CVE-2022-31813");
    expect(vulners.sources[0]!.severity).toBeUndefined();
    expect(vulners.mappings.cve).toEqual(["CVE-2022-31813", "CVE-2022-22720", "CVE-2022-30556"]);
    expect(vulners.sources[0]!.cvss).toEqual({ score: 9.8 });
  });

  it("places code findings on a repository asset", () => {
    const raw = parseSemgrep(fixture("semgrep/juice-shop.sarif"), { repository: "juice-shop" }).findings;
    const { findings, assets } = normalize(raw, { assessmentId: "lab", now });
    expect(assets).toEqual([{ id: "asset-repo-juice-shop", assessmentId: "lab", kind: "repository", name: "juice-shop", inScope: true, tags: [] }]);
    expect(findings).toHaveLength(7);
    expect(findings[0]!.assetId).toBe("asset-repo-juice-shop");
    expect(findings[0]!.scope).toBe("routes/login.ts:34-36");
    expect(findings[0]!.risk).toEqual({ severity: "high" });
    expect(findings[0]!.sources[0]!.severity).toBe("high");
  });

  it("places image findings on a container-image asset", () => {
    const raw = parseTrivy(fixture("trivy/juice-shop-image.json")).findings;
    const { findings, assets } = normalize(raw, { assessmentId: "lab", now });
    expect(assets).toEqual([
      { id: "asset-image-bkimminich-juice-shop-v17-1-1", assessmentId: "lab", kind: "container-image", name: "bkimminich/juice-shop:v17.1.1", inScope: true, tags: [] },
    ]);
    expect(findings).toHaveLength(6);
    const jwt = findings[2]!;
    expect(jwt.assetId).toBe("asset-image-bkimminich-juice-shop-v17-1-1");
    expect(jwt.risk).toEqual({ severity: "critical" });
    expect(jwt.sources[0]).toEqual({
      tool: "trivy",
      rawId: "CVE-2015-9235@jsonwebtoken",
      reference: "https://avd.aquasec.com/nvd/cve-2015-9235",
      severity: "critical",
      cvss: { vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 },
    });
    expect(jwt.fix).toBe("Upgrade jsonwebtoken from 0.4.0 to 4.2.2 or later.");
  });

  it("places cloud findings on one account asset, tagged with the provider", () => {
    const raw = parseProwler(fixture("prowler/lab-account.ocsf.json")).findings;
    const { findings, assets } = normalize(raw, { assessmentId: "lab", now });
    expect(assets).toEqual([{ id: "asset-cloud-aws-123456789012", assessmentId: "lab", kind: "cloud-account", name: "retest-lab (aws 123456789012)", inScope: true, tags: ["aws"] }]);
    expect(findings).toHaveLength(7);
    expect(findings[2]!.scope).toBe("arn:aws:s3:::juice-shop-uploads");
    expect(findings[2]!.risk).toEqual({ severity: "critical" });
  });

  it("reuses a repository, image or account asset that is passed in", () => {
    const repo = AssetSchema.parse({ id: "asset-1", assessmentId: "lab", kind: "repository", name: "juice-shop" });
    const raw = parseSemgrep(fixture("semgrep/juice-shop.sarif"), { repository: "juice-shop" }).findings;
    const { findings, assets } = normalize(raw, { assessmentId: "lab", now, assets: [repo] });
    expect(assets).toEqual([repo]);
    expect(findings.every((f) => f.assetId === "asset-1")).toBe(true);
  });

  it("refuses a raw finding it cannot place on an asset", () => {
    const lost: RawFinding = {
      tool: "nuclei",
      rawId: "x",
      title: "No host",
      scope: "/",
      cwe: [],
      cve: [],
      references: [],
      evidence: [],
      tags: [],
    };
    expect(() => normalize([lost], { assessmentId: "lab", now })).toThrow(/no host, url, repository, image or cloud account/);
  });

  it("cuts a title or a scope that is longer than the schema allows", () => {
    const long: RawFinding = {
      tool: "nuclei",
      rawId: "long",
      title: "x".repeat(300),
      url: "http://127.0.0.1:3000/" + "a".repeat(600),
      host: "127.0.0.1",
      port: 3000,
      scope: "GET /" + "a".repeat(600),
      cwe: [],
      cve: [],
      references: [],
      evidence: [],
      tags: [],
    };
    const { findings } = normalize([long], { assessmentId: "lab", now });
    expect(findings[0]!.title).toHaveLength(200);
    expect(findings[0]!.title.endsWith("…")).toBe(true);
    expect(findings[0]!.scope).toHaveLength(500);
    expect(FindingSchema.safeParse(findings[0]).success).toBe(true);
  });
});
