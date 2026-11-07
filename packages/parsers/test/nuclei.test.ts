import { describe, expect, it } from "vitest";
import { nucleiFindings, parseNuclei, parseNucleiLine } from "../src/nuclei.js";
import { fixture } from "./helpers.js";

const juiceShop = fixture("nuclei/juice-shop.jsonl");
const damaged = fixture("nuclei/damaged.jsonl");

describe("parseNucleiLine", () => {
  const first = juiceShop.split("\n")[0]!;

  it("reads one result: template, info, where it matched and when", () => {
    const r = parseNucleiLine(first);
    expect(r.templateId).toBe("tech-detect");
    expect(r.templateUrl).toBe("https://github.com/projectdiscovery/nuclei-templates/blob/main/http/technologies/tech-detect.yaml");
    expect(r.name).toBe("Wappalyzer Technology Detection");
    expect(r.severity).toBe("info");
    expect(r.tags).toEqual(["tech"]);
    expect(r.authors).toEqual(["hakluke"]);
    expect(r.matcherName).toBe("express");
    expect(r.type).toBe("http");
    expect(r.host).toBe("http://127.0.0.1:3000");
    expect(r.ip).toBe("127.0.0.1");
    expect(r.port).toBe(3000);
    expect(r.matchedAt).toBe("http://127.0.0.1:3000");
    expect(r.timestamp).toBe("2026-11-07T18:12:40.918204+01:00");
    expect(r.request?.startsWith("GET / HTTP/1.1\r\nHost: 127.0.0.1:3000")).toBe(true);
    expect(r.response?.startsWith("HTTP/1.1 200 OK")).toBe(true);
    expect(r.curlCommand?.startsWith("curl -X 'GET'")).toBe(true);
    expect(r.description).toBeUndefined();
    expect(r.classification).toBeUndefined();
  });

  it("reads the classification block: CWE ids, CVSS vector and score", () => {
    const metrics = juiceShop.split("\n").find((l) => l.includes('"template-id":"prometheus-metrics"'))!;
    const r = parseNucleiLine(metrics);
    expect(r.severity).toBe("medium");
    expect(r.classification).toEqual({
      cweIds: ["CWE-200"],
      cveIds: [],
      cvssMetrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
      cvssScore: 5.3,
    });
    expect(r.remediation).toBe("Restrict access to the metrics endpoint or move it to an internal listener.");
  });

  it("reads the extracted results and the references", () => {
    const robots = juiceShop.split("\n").find((l) => l.includes('"template-id":"robots-txt-endpoint"'))!;
    expect(parseNucleiLine(robots).extractedResults).toEqual(["Disallow: /ftp"]);
    const cors = juiceShop.split("\n").find((l) => l.includes('"template-id":"cors-misconfig"'))!;
    expect(parseNucleiLine(cors).references).toEqual(["https://portswigger.net/web-security/cors"]);
  });

  it("maps an unknown severity to info and says so", () => {
    const r = parseNucleiLine(first.replace('"severity":"info"', '"severity":"unknown"'));
    expect(r.severity).toBe("info");
  });

  it("refuses a line that is not JSON", () => {
    expect(() => parseNucleiLine('{"template-id": "x", "info": {"name": "cut')).toThrow(/not JSON/);
  });

  it("refuses a result without a template id", () => {
    expect(() => parseNucleiLine('{"info":{"name":"x","severity":"info"},"matched-at":"http://127.0.0.1:3000"}')).toThrow(
      /template-id/,
    );
  });
});

describe("parseNuclei: the Juice Shop run", () => {
  const result = parseNuclei(juiceShop);

  it("reads every line of the file", () => {
    expect(result.tool).toBe("nuclei");
    expect(result.results).toHaveLength(11);
    expect(result.findings).toHaveLength(11);
    expect(result.warnings).toEqual([]);
  });

  it("counts the templates and the severities exactly", () => {
    const byTemplate = new Map<string, number>();
    for (const r of result.results) byTemplate.set(r.templateId, (byTemplate.get(r.templateId) ?? 0) + 1);
    expect(Object.fromEntries(byTemplate)).toEqual({
      "tech-detect": 1,
      "http-missing-security-headers": 5,
      "robots-txt-endpoint": 1,
      "swagger-api": 1,
      "prometheus-metrics": 1,
      "options-method": 1,
      "cors-misconfig": 1,
    });
    const bySeverity = new Map<string, number>();
    for (const f of result.findings) bySeverity.set(f.severity ?? "none", (bySeverity.get(f.severity ?? "none") ?? 0) + 1);
    expect(Object.fromEntries(bySeverity)).toEqual({ info: 9, medium: 1, low: 1 });
  });
});

describe("nucleiFindings", () => {
  const { results } = parseNuclei(juiceShop);
  const findings = nucleiFindings(results);

  it("ids a result by its template, and by the matcher too when the template has several", () => {
    expect(findings.map((f) => f.rawId)).toEqual([
      "tech-detect:express",
      "http-missing-security-headers:content-security-policy",
      "http-missing-security-headers:strict-transport-security",
      "http-missing-security-headers:permissions-policy",
      "http-missing-security-headers:referrer-policy",
      "http-missing-security-headers:cross-origin-opener-policy",
      "robots-txt-endpoint",
      "swagger-api",
      "prometheus-metrics",
      "options-method",
      "cors-misconfig:arbitrary-origin",
    ]);
  });

  it("titles the finding with the template name and the matcher", () => {
    expect(findings[1]!.title).toBe("HTTP Missing Security Headers: content-security-policy");
    expect(findings[7]!.title).toBe("Public Swagger API - Detect");
  });

  it("points at the URL that matched, with the host and the port split out", () => {
    const swagger = findings[7]!;
    expect(swagger.tool).toBe("nuclei");
    expect(swagger.url).toBe("http://127.0.0.1:3000/api-docs/");
    expect(swagger.host).toBe("127.0.0.1");
    expect(swagger.port).toBe(3000);
    expect(swagger.protocol).toBe("tcp");
    expect(swagger.scope).toBe("GET /api-docs/");
    expect(swagger.phase).toBe("assessment");
    expect(swagger.detectedAt).toBe("2026-11-07T18:12:41.611540+01:00");
  });

  it("keeps the tool's own severity, CWE, CVSS and remediation", () => {
    const metrics = findings[8]!;
    expect(metrics.severity).toBe("medium");
    expect(metrics.cwe).toEqual([200]);
    expect(metrics.cve).toEqual([]);
    expect(metrics.cvss).toEqual({ vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 5.3 });
    expect(metrics.fix).toBe("Restrict access to the metrics endpoint or move it to an internal listener.");
    expect(metrics.description).toBe("Prometheus metrics page was detected.");
    expect(findings[0]!.cvss).toBeUndefined();
    expect(findings[0]!.fix).toBeUndefined();
  });

  it("puts the template page first in the references, then the template's own", () => {
    const cors = findings[10]!;
    expect(cors.references).toEqual([
      "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/generic/cors-misconfig.yaml",
      "https://portswigger.net/web-security/cors",
    ]);
    expect(cors.severity).toBe("low");
    expect(cors.cwe).toEqual([942]);
    expect(cors.scope).toBe("GET /rest/products/search?q=");
  });

  it("carries the request and the response as one evidence block, then what was extracted", () => {
    const robots = findings[6]!;
    expect(robots.evidence).toHaveLength(2);
    expect(robots.evidence[0]!.kind).toBe("request-response");
    expect(robots.evidence[0]!.title).toBe("GET http://127.0.0.1:3000/robots.txt");
    expect(robots.evidence[0]!.content).toBe(
      "GET /robots.txt HTTP/1.1\r\nHost: 127.0.0.1:3000\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n" +
        "\n" +
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 28\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain; charset=utf-8\r\nDate: Sat, 07 Nov 2026 17:12:41 GMT\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n\r\nUser-agent: *\nDisallow: /ftp\n",
    );
    expect(robots.evidence[1]).toEqual({ kind: "scanner-output", title: "Extracted by robots-txt-endpoint", content: "Disallow: /ftp" });
    expect(findings[0]!.evidence).toHaveLength(1);
  });

  it("uses the method of the request in the scope", () => {
    expect(findings[9]!.scope).toBe("OPTIONS /rest/user/whoami");
  });

  it("tags with the template's tags", () => {
    expect(findings[8]!.tags).toEqual(["config", "exposure", "prometheus"]);
  });
});

describe("parseNuclei: a damaged file", () => {
  const result = parseNuclei(damaged);

  it("keeps the good lines, skips the blank ones and reports the bad ones with their line number", () => {
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.rawId).toBe("swagger-api");
    expect(result.warnings).toHaveLength(2);
    expect(result.warnings[0]).toMatch(/^line 2: not JSON/);
    expect(result.warnings[1]).toMatch(/^line 4: .*template-id/);
  });

  it("returns nothing for an empty file, without complaint", () => {
    expect(parseNuclei("")).toMatchObject({ findings: [], results: [], warnings: [] });
    expect(parseNuclei("\n\n")).toMatchObject({ findings: [], results: [], warnings: [] });
  });
});
