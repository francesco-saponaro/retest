import { describe, expect, it } from "vitest";
import {
  CvssError,
  CvssSchema,
  baseScore,
  exploitabilitySubScore,
  formatVector,
  impactSubScore,
  parseVector,
  roundUp,
  scoreVector,
  temporalScore,
} from "../src/cvss.js";

// Vectors and scores from the CVSS v3.1 examples published by FIRST
// (https://www.first.org/cvss/v3.1/examples) plus the v3.1 user guide.
const official: Array<[string, string, number]> = [
  ["CVE-2013-1937 phpMyAdmin reflected XSS", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1],
  ["CVE-2013-0375 MySQL stored SQL injection", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4],
  ["CVE-2014-3566 SSLv3 POODLE", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1],
  ["CVE-2012-1516 VMware guest to host escape", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1],
  ["CVE-2009-0658 Adobe Acrobat buffer overflow", "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8],
  ["CVE-2011-1265 Windows Bluetooth stack", "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8],
  ["CVE-2014-2019 iOS Find My iPhone bypass", "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 4.6],
  ["CVE-2014-0160 OpenSSL Heartbleed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5],
  ["CVE-2014-6271 Bash Shellshock", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0],
  ["CVE-2016-1645 Chrome PDFium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8],
  ["CVE-2014-0224 OpenSSL CCS injection", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4],
];

describe("parseVector", () => {
  it("parses the eight base metrics", () => {
    const v = parseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
    expect(v).toEqual({
      version: "3.1",
      AV: "N",
      AC: "L",
      PR: "N",
      UI: "N",
      S: "U",
      C: "H",
      I: "N",
      A: "N",
    });
  });

  it("accepts the metrics in any order", () => {
    const a = parseVector("CVSS:3.1/A:N/I:N/C:H/S:U/UI:N/PR:N/AC:L/AV:N");
    const b = parseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
    expect(a).toEqual(b);
  });

  it("parses optional temporal metrics", () => {
    const v = parseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:P/RL:O/RC:C");
    expect(v.E).toBe("P");
    expect(v.RL).toBe("O");
    expect(v.RC).toBe("C");
  });

  it("accepts a 3.0 prefix and keeps the version", () => {
    expect(parseVector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").version).toBe("3.0");
  });

  it.each([
    ["no prefix", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"],
    ["wrong version", "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"],
    ["missing metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N"],
    ["duplicate metric", "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"],
    ["bad value", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"],
    ["unknown metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/ZZ:H"],
    ["environmental metric, which is not supported", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/CR:H"],
    ["empty", ""],
  ])("rejects %s", (_name, vector) => {
    expect(() => parseVector(vector)).toThrow(CvssError);
  });
});

describe("roundUp", () => {
  it("rounds up to one decimal", () => {
    expect(roundUp(4.02)).toBe(4.1);
    expect(roundUp(4.0)).toBe(4.0);
    expect(roundUp(4.01)).toBe(4.1);
  });

  it("ignores floating point noise below the fifth decimal, as the 3.1 spec requires", () => {
    expect(roundUp(4.000000001)).toBe(4.0);
    expect(roundUp(8.700000000000001)).toBe(8.7);
  });
});

describe("baseScore", () => {
  it.each(official)("%s scores %s", (_name, vector, expected) => {
    expect(baseScore(vector)).toBe(expected);
  });

  it("is 0 when there is no impact at all", () => {
    expect(baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
    expect(baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N")).toBe(0);
  });

  it("caps at 10", () => {
    expect(baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")).toBe(10);
  });

  it("uses the higher privilege weights when the scope changes", () => {
    const unchanged = baseScore("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
    const changed = baseScore("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
    expect(unchanged).toBe(5.4);
    expect(changed).toBe(6.4);
  });

  it("accepts a parsed vector as well as a string", () => {
    const v = parseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
    expect(baseScore(v)).toBe(7.5);
  });
});

describe("sub scores", () => {
  it("match the Heartbleed worked example", () => {
    const v = parseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
    expect(impactSubScore(v)).toBeCloseTo(3.5952, 4);
    expect(exploitabilitySubScore(v)).toBeCloseTo(3.887, 3);
  });
});

describe("temporalScore", () => {
  it("equals the base score when no temporal metrics are given", () => {
    expect(temporalScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")).toBe(7.5);
  });

  it("lowers the score for a proof of concept with an official fix and confirmed report", () => {
    // 7.5 x 0.94 x 0.95 x 1.0 = 6.6975 -> 6.7
    expect(temporalScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:P/RL:O/RC:C")).toBe(6.7);
  });

  it("treats X as not defined", () => {
    expect(temporalScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:X/RL:X/RC:X")).toBe(7.5);
  });
});

describe("formatVector", () => {
  it("writes the metrics back in the canonical order", () => {
    const v = parseVector("CVSS:3.1/A:N/I:N/C:H/S:U/UI:N/PR:N/AC:L/AV:N/RC:C");
    expect(formatVector(v)).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/RC:C");
  });
});

describe("scoreVector", () => {
  it("returns the scores and the qualitative severity together", () => {
    const r = scoreVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:P/RL:O/RC:C");
    expect(r.vector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:P/RL:O/RC:C");
    expect(r.baseScore).toBe(7.5);
    expect(r.temporalScore).toBe(6.7);
    expect(r.severity).toBe("high");
  });

  it("maps 0 to info and 10 to critical", () => {
    expect(scoreVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").severity).toBe("info");
    expect(scoreVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").severity).toBe("critical");
  });
});

describe("CvssSchema", () => {
  it("accepts a vector with its base score", () => {
    const r = CvssSchema.safeParse({ vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", baseScore: 7.5 });
    expect(r.success).toBe(true);
  });

  it("rejects a vector string that does not parse", () => {
    const r = CvssSchema.safeParse({ vector: "CVSS:3.1/AV:N", baseScore: 7.5 });
    expect(r.success).toBe(false);
  });

  it("rejects a score that does not match the vector", () => {
    const r = CvssSchema.safeParse({ vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", baseScore: 9.8 });
    expect(r.success).toBe(false);
  });
});
