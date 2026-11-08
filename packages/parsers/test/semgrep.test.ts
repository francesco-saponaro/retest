import { describe, expect, it } from "vitest";
import { parseSarif, parseSemgrep, semgrepFindings } from "../src/semgrep.js";
import { fixture } from "./helpers.js";

const sarif = fixture("semgrep/juice-shop.sarif");

describe("parseSarif", () => {
  const log = parseSarif(sarif);

  it("reads the tool, its rules and its results", () => {
    expect(log.version).toBe("2.1.0");
    expect(log.runs).toHaveLength(1);
    const run = log.runs[0]!;
    expect(run.tool.name).toBe("Semgrep OSS");
    expect(run.tool.version).toBe("1.142.0");
    expect(run.rules).toHaveLength(6);
    expect(run.results).toHaveLength(7);
  });

  it("reads a rule: id, level, text, help link, and the CWE and OWASP tags", () => {
    const rule = parseSarif(sarif).runs[0]!.rules[0]!;
    expect(rule.id).toBe("javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection");
    expect(rule.level).toBe("error");
    expect(rule.description.startsWith("Detected a sequelize statement that is tainted by user-input.")).toBe(true);
    expect(rule.helpUri).toBe("https://semgrep.dev/r/javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection");
    expect(rule.tags).toContain("security");
    expect(rule.cwe).toEqual([89]);
    expect(rule.owasp).toEqual(["A01:2017", "A03:2021"]);
    expect(rule.precision).toBe("very-high");
    expect(rule.references).toEqual(["https://sequelize.org/docs/v6/core-concepts/raw-queries/#replacements"]);
  });

  it("reads a result: rule, file, lines, snippet, message, fingerprint", () => {
    const r = log.runs[0]!.results[0]!;
    expect(r.ruleId).toBe("javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection");
    expect(r.level).toBe("error"); // from the rule's default when the result does not say
    expect(r.file).toBe("routes/login.ts");
    expect(r.startLine).toBe(34);
    expect(r.endLine).toBe(36);
    expect(r.snippet?.trim().startsWith("models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email")).toBe(true);
    expect(r.message.startsWith("Detected a sequelize statement")).toBe(true);
    expect(r.fingerprint).toBe("4f0c2b9d8a1e6f3c7b5d2a9e1c8f4b6d0a3e7c9f2b5d8a1e4c7f0b3d6a9e2c5f_0");
  });

  it("refuses anything that is not SARIF", () => {
    expect(() => parseSarif("<xml/>")).toThrow(/not JSON/);
    expect(() => parseSarif('{"version": "2.1.0"}')).toThrow(/not a SARIF log/);
    expect(() => parseSarif('{"version": "1.0", "runs": []}')).toThrow(/not a SARIF log/);
  });
});

describe("semgrepFindings", () => {
  const findings = semgrepFindings(parseSarif(sarif), { repository: "juice-shop" });

  it("makes one raw finding per result, on the repository, in the assessment phase", () => {
    expect(findings).toHaveLength(7);
    for (const f of findings) {
      expect(f.tool).toBe("semgrep");
      expect(f.repository).toBe("juice-shop");
      expect(f.phase).toBe("assessment");
      expect(f.url).toBeUndefined();
      expect(f.host).toBeUndefined();
    }
    expect(findings.map((f) => f.filePath)).toEqual([
      "routes/login.ts",
      "routes/search.ts",
      "routes/fileServer.ts",
      "routes/redirect.ts",
      "lib/insecurity.ts",
      "frontend/src/app/search-result/search-result.component.ts",
      "server.ts",
    ]);
  });

  it("names the finding after the rule's last segment and places it at file:line", () => {
    const sqli = findings[0]!;
    expect(sqli.title).toBe("express-sequelize-injection in routes/login.ts");
    expect(sqli.scope).toBe("routes/login.ts:34-36");
    expect(findings[1]!.scope).toBe("routes/search.ts:23");
    // The rule id is the raw id, with the location, because one rule fires in several places.
    expect(sqli.rawId).toBe("javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection@routes/login.ts:34");
    expect(findings[1]!.rawId).toBe("javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection@routes/search.ts:23");
  });

  it("maps the level to a severity: error high, warning medium, note low", () => {
    expect(findings.map((f) => f.severity)).toEqual(["high", "high", "medium", "medium", "medium", "medium", "medium"]);
  });

  it("keeps the rule's CWE, its message as the description, its help link first in the references", () => {
    const traversal = findings[2]!;
    expect(traversal.cwe).toEqual([22]);
    expect(traversal.cve).toEqual([]);
    expect(traversal.description?.startsWith("Detected possible user input going into a `path.join` or `path.resolve` function.")).toBe(true);
    expect(traversal.references).toEqual([
      "https://semgrep.dev/r/javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal",
      "https://owasp.org/www-community/attacks/Path_Traversal",
    ]);
    expect(traversal.fix).toBeUndefined();
    expect(traversal.impact).toBeUndefined();
    expect(traversal.tags).toEqual(["security", "owasp:A05:2017", "owasp:A01:2021", "semgrep-precision:very-high"]);
  });

  it("puts the matched lines in the evidence", () => {
    const md5 = findings[4]!;
    expect(md5.evidence).toEqual([
      {
        kind: "scanner-output",
        title: "lib/insecurity.ts:36",
        content: "export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')",
      },
    ]);
  });

  it("names the repository `source` when none is given", () => {
    expect(semgrepFindings(parseSarif(sarif))[0]!.repository).toBe("source");
  });
});

describe("parseSemgrep", () => {
  it("returns the findings and warns about results whose rule is missing from the run", () => {
    const r = parseSemgrep(sarif, { repository: "juice-shop" });
    expect(r.tool).toBe("semgrep");
    expect(r.findings).toHaveLength(7);
    expect(r.warnings).toEqual([]);

    const broken = JSON.parse(sarif);
    broken.runs[0].results.push({ ruleId: "javascript.lang.security.detect-eval-with-expression", message: { text: "eval" }, locations: [] });
    const r2 = parseSemgrep(JSON.stringify(broken), { repository: "juice-shop" });
    expect(r2.findings).toHaveLength(7);
    expect(r2.warnings).toEqual(["result 8 (javascript.lang.security.detect-eval-with-expression) has no location; skipped"]);
  });
});
