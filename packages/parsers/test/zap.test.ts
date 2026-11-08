import { describe, expect, it } from "vitest";
import { parseZap, parseZapReport, zapFindings } from "../src/zap.js";
import { fixture } from "./helpers.js";

const report = fixture("zap/juice-shop.json");

describe("parseZapReport", () => {
  const r = parseZapReport(report);

  it("reads the report header and the one site", () => {
    expect(r.programName).toBe("ZAP");
    expect(r.version).toBe("2.16.1");
    expect(r.generated).toBe("Sun, 8 Nov 2026 18:41:07");
    expect(r.sites).toHaveLength(1);
    const site = r.sites[0]!;
    expect(site.name).toBe("http://127.0.0.1:3000");
    expect(site.host).toBe("127.0.0.1");
    expect(site.port).toBe(3000);
    expect(site.ssl).toBe(false);
    expect(site.alerts).toHaveLength(6);
  });

  it("reads one alert whole: plugin, risk, confidence, CWE, instances, text without the HTML", () => {
    const csp = r.sites[0]!.alerts[0]!;
    expect(csp.pluginId).toBe("10038");
    expect(csp.alertRef).toBe("10038-1");
    expect(csp.name).toBe("Content Security Policy (CSP) Header Not Set");
    expect(csp.risk).toBe("medium");
    expect(csp.confidence).toBe("high");
    expect(csp.cweId).toBe(693);
    expect(csp.wascId).toBe(15);
    expect(csp.count).toBe(3);
    expect(csp.instances.map((i) => i.uri)).toEqual(["http://127.0.0.1:3000/", "http://127.0.0.1:3000/ftp", "http://127.0.0.1:3000/robots.txt"]);
    expect(csp.description.startsWith("Content Security Policy (CSP) is an added layer of security")).toBe(true);
    expect(csp.description).not.toContain("<p>");
    expect(csp.description).toContain("load on that page — covered types"); // &#x2014; decoded
    expect(csp.solution).toBe("Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.");
    expect(csp.references).toHaveLength(7);
    expect(csp.references[0]).toBe("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy");
  });

  it("keeps each instance's evidence and the other info", () => {
    const cors = r.sites[0]!.alerts[1]!;
    expect(cors.pluginId).toBe("10098");
    expect(cors.risk).toBe("medium");
    expect(cors.confidence).toBe("medium");
    expect(cors.cweId).toBe(264);
    expect(cors.instances[0]).toEqual({
      uri: "http://127.0.0.1:3000/rest/products/search?q=",
      method: "GET",
      param: "",
      attack: "",
      evidence: "Access-Control-Allow-Origin: *",
      otherInfo: expect.stringContaining("permits cross-domain read requests from arbitrary third party domains"),
    });
    // Two paragraphs in the solution become two lines.
    expect(cors.solution.split("\n")).toHaveLength(2);
  });

  it("maps every risk code: 0 info, 1 low, 2 medium, 3 high", () => {
    expect(r.sites[0]!.alerts.map((a) => a.risk)).toEqual(["medium", "medium", "low", "low", "low", "info"]);
    expect(r.sites[0]!.alerts.map((a) => a.confidence)).toEqual(["high", "medium", "medium", "low", "low", "low"]);
  });

  it("refuses anything that is not a ZAP report", () => {
    expect(() => parseZapReport("not json")).toThrow(/not JSON/);
    expect(() => parseZapReport('{"site": "nope"}')).toThrow(/not a ZAP JSON report/);
    expect(() => parseZapReport('{"@programName": "Burp", "site": []}')).toThrow(/not a ZAP JSON report/);
  });
});

describe("zapFindings", () => {
  const findings = zapFindings(parseZapReport(report));

  it("makes one raw finding per alert, not per instance", () => {
    expect(findings).toHaveLength(6);
    expect(findings.map((f) => f.rawId)).toEqual(["10038", "10098", "10063", "10110", "10096", "10027"]);
    for (const f of findings) {
      expect(f.tool).toBe("zap");
      expect(f.phase).toBe("assessment");
      expect(f.url).toBe("http://127.0.0.1:3000");
      expect(f.host).toBe("127.0.0.1");
      expect(f.port).toBe(3000);
    }
  });

  it("fills the finding from the alert: ZAP's risk as severity, its solution as the fix, its CWE", () => {
    const csp = findings[0]!;
    expect(csp.title).toBe("Content Security Policy (CSP) Header Not Set");
    expect(csp.severity).toBe("medium");
    expect(csp.cwe).toEqual([693]);
    expect(csp.cve).toEqual([]);
    expect(csp.fix).toBe("Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.");
    expect(csp.description?.startsWith("Content Security Policy (CSP)")).toBe(true);
    expect(csp.impact).toBeUndefined();
    expect(csp.references[0]).toBe("https://www.zaproxy.org/docs/alerts/10038/");
    expect(csp.references).toHaveLength(8);
    expect(csp.tags).toEqual(["zap-confidence:high", "wasc-15"]);
  });

  it("writes the scope from the instances: the paths, up to three, then a count", () => {
    expect(findings[0]!.scope).toBe("GET /, GET /ftp, GET /robots.txt");
    expect(findings[3]!.scope).toBe("GET /main.js");
    const many = zapFindings({
      ...parseZapReport(report),
      sites: [
        {
          ...parseZapReport(report).sites[0]!,
          alerts: [
            {
              ...parseZapReport(report).sites[0]!.alerts[0]!,
              instances: ["/a", "/b", "/c", "/d", "/e"].map((p) => ({ uri: `http://127.0.0.1:3000${p}`, method: "GET", param: "", attack: "", evidence: "", otherInfo: "" })),
            },
          ],
        },
      ],
    });
    expect(many[0]!.scope).toBe("GET /a, GET /b, GET /c and 2 more");
  });

  it("turns the instances into one scanner-output evidence block with the evidence strings", () => {
    const cors = findings[1]!;
    expect(cors.evidence).toHaveLength(1);
    expect(cors.evidence[0]!.kind).toBe("scanner-output");
    expect(cors.evidence[0]!.title).toBe("3 instances reported by ZAP");
    expect(cors.evidence[0]!.content.split("\n")).toEqual([
      "GET http://127.0.0.1:3000/rest/products/search?q=",
      "  evidence: Access-Control-Allow-Origin: *",
      "GET http://127.0.0.1:3000/api/Quantitys/",
      "  evidence: Access-Control-Allow-Origin: *",
      "GET http://127.0.0.1:3000/rest/user/whoami",
      "  evidence: Access-Control-Allow-Origin: *",
    ]);
    // An instance note that only repeats the alert's own "other info" is not written twice: the
    // alert's text goes once, at the end of the description.
    const comments = findings[5]!;
    expect(comments.evidence[0]!.content).toBe("GET http://127.0.0.1:3000/main.js\n  evidence: TODO");
    expect(comments.description).toBe(
      "The response appears to contain suspicious comments which may help an attacker.\nThe following pattern was used: \\bTODO\\b and was detected in likely comment: \"// TODO: Remove the debug code before release\", see evidence field for the suspicious comment/snippet.",
    );
    expect(findings[1]!.description?.split("\n")[1]?.startsWith("The CORS misconfiguration on the web server permits")).toBe(true);
    const stamp = findings[4]!;
    expect(stamp.evidence[0]!.content).toBe("GET http://127.0.0.1:3000/main.js\n  evidence: 1734567890");
    expect(stamp.description).toContain("\n1734567890, which evaluates to: 2024-12-19 00:24:50.");
    // A note that says something of its own is kept.
    const parsed = parseZapReport(report);
    parsed.sites[0]!.alerts[4]!.instances[0]!.otherInfo = "Seen in the second script tag.";
    expect(zapFindings(parsed)[4]!.evidence[0]!.content).toBe("GET http://127.0.0.1:3000/main.js\n  evidence: 1734567890\n  note: Seen in the second script tag.");
  });

  it("stamps the finding with the report's time", () => {
    expect(findings[0]!.detectedAt).toBe("2026-11-08T18:41:07.000Z");
  });
});

describe("parseZap", () => {
  it("returns findings and no warnings for a clean report", () => {
    const r = parseZap(report);
    expect(r.tool).toBe("zap");
    expect(r.findings).toHaveLength(6);
    expect(r.warnings).toEqual([]);
  });

  it("warns about a site with no alerts and about an alert with no instances, and keeps going", () => {
    const parsed = JSON.parse(report);
    parsed.site.push({ "@name": "http://127.0.0.1:8080", "@host": "127.0.0.1", "@port": "8080", "@ssl": "false", alerts: [] });
    parsed.site[0].alerts[5].instances = [];
    const r = parseZap(JSON.stringify(parsed));
    expect(r.findings).toHaveLength(5);
    expect(r.warnings).toEqual([
      "alert 10027 (Information Disclosure - Suspicious Comments) has no instances; skipped",
      "site http://127.0.0.1:8080 has no alerts",
    ]);
  });
});
