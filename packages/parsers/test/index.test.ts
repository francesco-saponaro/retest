import type { Asset, Finding } from "@retest/schema";
import { describe, expect, it } from "vitest";
import { PARSEABLE_TOOLS, canParse, classify, dedupe, normalize, parse } from "../src/index.js";
import { fixture } from "./helpers.js";

describe("parse(tool, text)", () => {
  it("knows which tools have a parser", () => {
    expect(PARSEABLE_TOOLS).toEqual(["nmap", "nuclei", "zap", "semgrep", "trivy", "prowler"]);
    expect(canParse("nmap")).toBe(true);
    expect(canParse("zap")).toBe(true);
    expect(canParse("manual")).toBe(false);
  });

  it("routes to the right parser by tool name", () => {
    expect(parse("nmap", fixture("nmap/juice-shop.xml")).findings).toHaveLength(4);
    expect(parse("nuclei", fixture("nuclei/juice-shop.jsonl")).findings).toHaveLength(11);
    expect(parse("zap", fixture("zap/juice-shop.json")).findings).toHaveLength(6);
    expect(parse("semgrep", fixture("semgrep/juice-shop.sarif"), { repository: "juice-shop" }).findings).toHaveLength(7);
    expect(parse("trivy", fixture("trivy/juice-shop-image.json")).findings).toHaveLength(6);
    expect(parse("prowler", fixture("prowler/lab-account.ocsf.json")).findings).toHaveLength(7);
  });

  it("passes the options through to the parser that takes them", () => {
    expect(parse("semgrep", fixture("semgrep/juice-shop.sarif"), { repository: "juice-shop" }).findings[0]!.repository).toBe("juice-shop");
    expect(parse("semgrep", fixture("semgrep/juice-shop.sarif")).findings[0]!.repository).toBe("source");
  });

  it("says plainly when a tool has no parser", () => {
    expect(() => parse("manual", "{}")).toThrow("no parser for manual");
  });

  it("goes from a file to findings in two calls", () => {
    const raw = parse("nuclei", fixture("nuclei/juice-shop.jsonl"));
    const { findings, assets } = normalize(raw.findings, { assessmentId: "lab" });
    expect(findings).toHaveLength(11);
    expect(assets).toHaveLength(1);
  });

  it("runs the whole lab through the pipeline: parse, normalize, dedupe, classify", () => {
    const now = new Date("2026-11-08T19:00:00Z");
    const runs: [Parameters<typeof parse>[0], string, Parameters<typeof parse>[2]][] = [
      ["nmap", "nmap/juice-shop.xml", undefined],
      ["nuclei", "nuclei/juice-shop.jsonl", undefined],
      ["zap", "zap/juice-shop.json", undefined],
      ["semgrep", "semgrep/juice-shop.sarif", { repository: "juice-shop" }],
      ["trivy", "trivy/juice-shop-image.json", undefined],
      ["prowler", "prowler/lab-account.ocsf.json", undefined],
    ];
    const assets: Asset[] = [];
    const all: Finding[] = [];
    for (const [tool, file, options] of runs) {
      const raw = parse(tool, fixture(file), options);
      const n = normalize(raw.findings, { assessmentId: "lab", now, assets });
      assets.push(...n.assets.filter((a) => !assets.some((k) => k.id === a.id)));
      all.push(...n.findings);
    }
    expect(all).toHaveLength(4 + 11 + 6 + 7 + 6 + 7);
    expect(assets.map((a) => a.id)).toEqual([
      "asset-host-127-0-0-1",
      "asset-web-127-0-0-1-3000",
      "asset-repo-juice-shop",
      "asset-image-bkimminich-juice-shop-v17-1-1",
      "asset-cloud-aws-123456789012",
    ]);
    const { findings, merged } = dedupe(all, { now });
    expect(findings).toHaveLength(41 - 4); // three web pairs and one Trivy pair
    expect(merged).toHaveLength(4);
    const { findings: classified, unmapped, notes } = classify(findings, { now });
    expect(classified).toHaveLength(37);
    expect(unmapped).toEqual({ cwe: [], checks: [] });
    expect(notes).toEqual([]);
    const bySeverity = Object.fromEntries(["critical", "high", "medium", "low", "info"].map((s) => [s, classified.filter((f) => f.risk.severity === s).length]));
    expect(bySeverity).toEqual({ critical: 4, high: 7, medium: 11, low: 3, info: 12 });
    expect(classified.filter((f) => f.risk.cvss).length).toBe(6); // five Trivy rows after the merge, plus the Nuclei metrics vector
  });
});
