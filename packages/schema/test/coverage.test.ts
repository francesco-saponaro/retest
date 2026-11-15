import { describe, expect, it } from "vitest";
import { OWASP_TOP_10_2021_IDS, TOOL_OWASP_TOP10, toolsThatLookFor } from "../src/index.js";

describe("which tools look for which OWASP Top 10 category", () => {
  it("names only real categories, and no tool claims A04 Insecure Design", () => {
    for (const ids of Object.values(TOOL_OWASP_TOP10)) {
      for (const id of ids) expect(OWASP_TOP_10_2021_IDS).toContain(id);
      expect(ids).not.toContain("A04");
    }
  });

  it("answers per category, only among the tools that ran", () => {
    expect(toolsThatLookFor("A06", ["trivy", "zap"])).toEqual(["zap", "trivy"]);
    expect(toolsThatLookFor("A03", ["trivy", "zap"])).toEqual([]);
    expect(toolsThatLookFor("A09", ["nmap", "nuclei", "zap", "semgrep", "trivy", "prowler"])).toEqual(["prowler"]);
    expect(toolsThatLookFor("A04", ["nmap", "nuclei", "zap", "semgrep", "trivy", "prowler"])).toEqual([]);
  });

  it("does not count a manual entry as a tool that looked", () => {
    expect(toolsThatLookFor("A01", ["manual"])).toEqual([]);
  });
});
