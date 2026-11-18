import { describe, expect, it } from "vitest";
import { parseCommand } from "../src/args.js";

describe("parseCommand", () => {
  it("reads an import: the tool, the file and the assessment, in any order", () => {
    expect(parseCommand(["import", "--tool", "nmap", "scan.xml", "--assessment", "a-1"])).toEqual({ kind: "import", tool: "nmap", file: "scan.xml", assessment: "a-1" });
    expect(parseCommand(["import", "zap.json", "--assessment=a-1", "--tool=zap"])).toEqual({ kind: "import", tool: "zap", file: "zap.json", assessment: "a-1" });
    expect(parseCommand(["import", "--tool", "semgrep", "s.sarif", "--assessment", "a-1", "--repository", "juice-shop"])).toEqual({
      kind: "import",
      tool: "semgrep",
      file: "s.sarif",
      assessment: "a-1",
      repository: "juice-shop",
    });
    expect(parseCommand(["import", "--tool", "trivy", "t.json", "--assessment", "a-1", "--image", "bkimminich/juice-shop:v17.1.1"])).toEqual({
      kind: "import",
      tool: "trivy",
      file: "t.json",
      assessment: "a-1",
      image: "bkimminich/juice-shop:v17.1.1",
    });
  });

  it("refuses an import with a tool it has no parser for, or without the file or the assessment", () => {
    expect(parseCommand(["import", "--tool", "nessus", "x", "--assessment", "a"])).toEqual({ kind: "error", message: "--tool must be one of nmap, nuclei, zap, semgrep, trivy, prowler" });
    expect(parseCommand(["import", "--tool", "nmap", "--assessment", "a"])).toEqual({ kind: "error", message: "import needs the file to read" });
    expect(parseCommand(["import", "--tool", "nmap", "scan.xml"])).toEqual({ kind: "error", message: "import needs --assessment <id>" });
  });

  it("reads a report: the technical one by default, the summary on request, to a file or to stdout", () => {
    expect(parseCommand(["report", "a-1"])).toEqual({ kind: "report", assessment: "a-1", summary: false });
    expect(parseCommand(["report", "a-1", "--summary", "--out", "s.md"])).toEqual({ kind: "report", assessment: "a-1", summary: true, out: "s.md" });
    expect(parseCommand(["report"])).toEqual({ kind: "error", message: "report needs the assessment id" });
  });

  it("creates an assessment from a name, its targets and who authorised it", () => {
    expect(parseCommand(["new", "--name", "Juice Shop lab", "--target", "127.0.0.1", "--target", "http://127.0.0.1:3000", "--authorized-by", "francesco"])).toEqual({
      kind: "new",
      name: "Juice Shop lab",
      targets: ["127.0.0.1", "http://127.0.0.1:3000"],
      exclusions: [],
      authorizedBy: "francesco",
    });
    expect(parseCommand(["new", "--name", "x", "--authorized-by", "me"])).toEqual({ kind: "error", message: "new needs at least one --target" });
  });

  it("lists the assessments, prints help, and names an unknown command or option", () => {
    expect(parseCommand(["assessments"])).toEqual({ kind: "assessments" });
    expect(parseCommand([])).toEqual({ kind: "help" });
    expect(parseCommand(["--help"])).toEqual({ kind: "help" });
    expect(parseCommand(["scan"])).toEqual({ kind: "error", message: "unknown command: scan" });
    expect(parseCommand(["report", "a", "--colour"])).toMatchObject({ kind: "error", message: expect.stringMatching(/--colour/) });
  });
});
