import { describe, expect, it } from "vitest";
import { parseTrivy, parseTrivyReport, trivyFindings } from "../src/trivy.js";
import { fixture } from "./helpers.js";

const image = fixture("trivy/juice-shop-image.json");

describe("parseTrivyReport", () => {
  const r = parseTrivyReport(image);

  it("reads what was scanned and when", () => {
    expect(r.schemaVersion).toBe(2);
    expect(r.artifactName).toBe("bkimminich/juice-shop:v17.1.1");
    expect(r.artifactType).toBe("container_image");
    expect(r.createdAt).toBe("2026-11-08T18:52:13.418266+01:00");
    expect(r.os).toEqual({ family: "alpine", name: "3.20.3" });
    expect(r.results).toHaveLength(3);
  });

  it("names the image by its tag when Trivy read a saved copy of it (docker save), not by the file", () => {
    const fromTar = JSON.parse(image) as Record<string, unknown>;
    fromTar.ArtifactName = "/out/juice-shop-image.tar";
    fromTar.Metadata = { ...(fromTar.Metadata as object), RepoTags: ["bkimminich/juice-shop:v17.1.1"] };
    expect(parseTrivyReport(JSON.stringify(fromTar)).artifactName).toBe("bkimminich/juice-shop:v17.1.1");
  });

  it("reads each result: target, class, type, and its vulnerabilities", () => {
    expect(r.results.map((x) => [x.target, x.class, x.type, x.vulnerabilities.length])).toEqual([
      ["bkimminich/juice-shop:v17.1.1 (alpine 3.20.3)", "os-pkgs", "alpine", 2],
      ["Node.js", "lang-pkgs", "node-pkg", 4],
      ["usr/local/lib/node_modules/npm/package.json", "lang-pkgs", "node-pkg", 0],
    ]);
  });

  it("reads one vulnerability whole", () => {
    const jwt = r.results[1]!.vulnerabilities[0]!;
    expect(jwt.id).toBe("CVE-2015-9235");
    expect(jwt.pkgName).toBe("jsonwebtoken");
    expect(jwt.pkgId).toBe("jsonwebtoken@0.4.0");
    expect(jwt.pkgPath).toBe("juice-shop/node_modules/jsonwebtoken/package.json");
    expect(jwt.installedVersion).toBe("0.4.0");
    expect(jwt.fixedVersion).toBe("4.2.2");
    expect(jwt.status).toBe("fixed");
    expect(jwt.severity).toBe("critical");
    expect(jwt.severitySource).toBe("ghsa");
    expect(jwt.title).toBe("Verification Bypass in jsonwebtoken");
    expect(jwt.description.startsWith("In jsonwebtoken node module before 4.2.2")).toBe(true);
    expect(jwt.cwe).toEqual([20, 327]);
    expect(jwt.primaryUrl).toBe("https://avd.aquasec.com/nvd/cve-2015-9235");
    expect(jwt.references).toHaveLength(5);
    expect(jwt.publishedAt).toBe("2018-05-29T20:29:00.98Z");
  });

  it("picks the v3 vector: NVD's when there is one, otherwise the first source that has one", () => {
    const jwt = r.results[1]!.vulnerabilities[0]!;
    expect(jwt.cvss).toEqual({ source: "nvd", vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 });
    const parsed = JSON.parse(image);
    delete parsed.Results[1].Vulnerabilities[0].CVSS.nvd;
    const again = parseTrivyReport(JSON.stringify(parsed)).results[1]!.vulnerabilities[0]!;
    expect(again.cvss).toEqual({ source: "ghsa", vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 });
    parsed.Results[1].Vulnerabilities[0].CVSS = { nvd: { V2Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", V2Score: 7.5 } };
    const v2only = parseTrivyReport(JSON.stringify(parsed)).results[1]!.vulnerabilities[0]!;
    expect(v2only.cvss).toBeUndefined();
  });

  it("maps UNKNOWN severity to info", () => {
    const parsed = JSON.parse(image);
    parsed.Results[1].Vulnerabilities[0].Severity = "UNKNOWN";
    expect(parseTrivyReport(JSON.stringify(parsed)).results[1]!.vulnerabilities[0]!.severity).toBe("info");
  });

  it("refuses anything that is not a Trivy report", () => {
    expect(() => parseTrivyReport("nope")).toThrow(/not JSON/);
    expect(() => parseTrivyReport('{"Results": []}')).toThrow(/not a Trivy JSON report/);
    expect(() => parseTrivyReport('{"SchemaVersion": 1, "ArtifactName": "x", "Results": []}')).toThrow(/not a Trivy JSON report/);
  });
});

describe("trivyFindings", () => {
  const findings = trivyFindings(parseTrivyReport(image));

  it("makes one raw finding per vulnerability row, on the image, in the assessment phase", () => {
    expect(findings).toHaveLength(6);
    for (const f of findings) {
      expect(f.tool).toBe("trivy");
      expect(f.image).toBe("bkimminich/juice-shop:v17.1.1");
      expect(f.phase).toBe("assessment");
      expect(f.detectedAt).toBe("2026-11-08T18:52:13.418266+01:00");
    }
    expect(findings.map((f) => f.rawId)).toEqual([
      "CVE-2024-9143@libcrypto3",
      "CVE-2024-9143@libssl3",
      "CVE-2015-9235@jsonwebtoken",
      "CVE-2020-15084@express-jwt",
      "CVE-2016-1000237@sanitize-html",
      "CVE-2017-16016@sanitize-html",
    ]);
  });

  it("names the finding after the CVE and the package, with the version as the scope", () => {
    const jwt = findings[2]!;
    expect(jwt.title).toBe("CVE-2015-9235 in jsonwebtoken 0.4.0: Verification Bypass in jsonwebtoken");
    expect(jwt.scope).toBe("jsonwebtoken@0.4.0");
    expect(findings[0]!.scope).toBe("libcrypto3@3.3.2-r0");
  });

  it("keeps the tool's severity, its CVE, its CWE and its CVSS claim", () => {
    const jwt = findings[2]!;
    expect(jwt.severity).toBe("critical");
    expect(jwt.cve).toEqual(["CVE-2015-9235"]);
    expect(jwt.cwe).toEqual([20, 327]);
    expect(jwt.cvss).toEqual({ vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 });
    expect(jwt.references[0]).toBe("https://avd.aquasec.com/nvd/cve-2015-9235");
    expect(jwt.references).toHaveLength(6);
  });

  it("writes the fix from the fixed version, and the evidence from the package row", () => {
    const jwt = findings[2]!;
    expect(jwt.fix).toBe("Upgrade jsonwebtoken from 0.4.0 to 4.2.2 or later.");
    expect(jwt.evidence).toEqual([
      {
        kind: "scanner-output",
        title: "Node.js: jsonwebtoken@0.4.0",
        content: [
          "package: jsonwebtoken",
          "installed: 0.4.0",
          "fixed in: 4.2.2",
          "status: fixed",
          "path: juice-shop/node_modules/jsonwebtoken/package.json",
          "source: GitHub Security Advisory npm (ghsa)",
          "severity: CRITICAL from ghsa",
        ].join("\n"),
      },
    ]);
    expect(jwt.description).toBe(
      "In jsonwebtoken node module before 4.2.2 it is possible for an attacker to bypass verification when a token digitally signed with an asymmetric key (RS/ES family) of algorithms but instead the attacker send a token digitally signed with a symmetric algorithm (HS* family).",
    );
    expect(jwt.tags).toEqual(["lang-pkgs", "node-pkg", "trivy-status:fixed"]);
  });

  it("says plainly when there is no fix yet", () => {
    const parsed = JSON.parse(image);
    delete parsed.Results[1].Vulnerabilities[0].FixedVersion;
    parsed.Results[1].Vulnerabilities[0].Status = "affected";
    const f = trivyFindings(parseTrivyReport(JSON.stringify(parsed)))[2]!;
    expect(f.fix).toBe("No fixed version of jsonwebtoken is available yet; track the advisory and consider replacing the package.");
  });
});

describe("parseTrivy", () => {
  it("returns the findings and says which targets had nothing", () => {
    const r = parseTrivy(image);
    expect(r.tool).toBe("trivy");
    expect(r.findings).toHaveLength(6);
    expect(r.warnings).toEqual([]);
    expect(r.report.results[2]!.vulnerabilities).toEqual([]);
  });

  it("warns about a vulnerability row without a CVSS v3 vector, because its severity cannot be checked", () => {
    const parsed = JSON.parse(image);
    parsed.Results[1].Vulnerabilities[0].CVSS = {};
    const r = parseTrivy(JSON.stringify(parsed));
    expect(r.findings).toHaveLength(6);
    expect(r.warnings).toEqual(["CVE-2015-9235 in jsonwebtoken has no CVSS v3 vector; its severity is Trivy's word only"]);
  });
});
