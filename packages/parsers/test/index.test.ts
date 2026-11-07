import { describe, expect, it } from "vitest";
import { PARSEABLE_TOOLS, canParse, normalize, parse } from "../src/index.js";
import { fixture } from "./helpers.js";

describe("parse(tool, text)", () => {
  it("knows which tools have a parser so far", () => {
    expect(PARSEABLE_TOOLS).toEqual(["nmap", "nuclei"]);
    expect(canParse("nmap")).toBe(true);
    expect(canParse("zap")).toBe(false);
    expect(canParse("manual")).toBe(false);
  });

  it("routes to the right parser by tool name", () => {
    expect(parse("nmap", fixture("nmap/juice-shop.xml")).findings).toHaveLength(4);
    expect(parse("nuclei", fixture("nuclei/juice-shop.jsonl")).findings).toHaveLength(11);
  });

  it("says plainly when a tool has no parser yet", () => {
    expect(() => parse("zap", "{}")).toThrow("no parser for zap yet");
  });

  it("goes from a file to findings in two calls", () => {
    const raw = parse("nuclei", fixture("nuclei/juice-shop.jsonl"));
    const { findings, assets } = normalize(raw.findings, { assessmentId: "lab" });
    expect(findings).toHaveLength(11);
    expect(assets).toHaveLength(1);
  });
});
