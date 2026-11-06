import { describe, expect, it } from "vitest";
import {
  ASVS_V4_CHAPTERS,
  AsvsChapterIdSchema,
  CIS_CONTROLS_V8,
  CisControlNumberSchema,
  OWASP_API_TOP_10_2023,
  OWASP_TOP_10_2021,
  OwaspApiTop10IdSchema,
  OwaspTop10IdSchema,
  asvsChapter,
  cisControl,
  lookupCwe,
  mappingsForOwaspTop10,
  owaspApiTop10,
  owaspTop10,
} from "../src/mappings/index.js";

describe("OWASP Top 10 2021", () => {
  it("has the ten categories in order", () => {
    expect(OWASP_TOP_10_2021.map((c) => c.id)).toEqual([
      "A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10",
    ]);
    expect(OWASP_TOP_10_2021[0]?.name).toBe("Broken Access Control");
    expect(OWASP_TOP_10_2021[2]?.name).toBe("Injection");
    expect(OWASP_TOP_10_2021[9]?.name).toBe("Server-Side Request Forgery");
  });

  it("looks a category up by id", () => {
    expect(owaspTop10("A05")?.name).toBe("Security Misconfiguration");
    expect(owaspTop10("A11")).toBeUndefined();
  });

  it("validates an id", () => {
    expect(OwaspTop10IdSchema.safeParse("A03").success).toBe(true);
    expect(OwaspTop10IdSchema.safeParse("A3").success).toBe(false);
  });

  it("gives every category a link to owasp.org", () => {
    for (const c of OWASP_TOP_10_2021) expect(c.url).toMatch(/^https:\/\/owasp\.org\//);
  });
});

describe("OWASP API Security Top 10 2023", () => {
  it("has the ten risks in order", () => {
    expect(OWASP_API_TOP_10_2023.map((c) => c.id)).toEqual([
      "API1", "API2", "API3", "API4", "API5", "API6", "API7", "API8", "API9", "API10",
    ]);
    expect(owaspApiTop10("API1")?.name).toBe("Broken Object Level Authorization");
    expect(owaspApiTop10("API4")?.name).toBe("Unrestricted Resource Consumption");
    expect(OwaspApiTop10IdSchema.safeParse("API10").success).toBe(true);
    expect(OwaspApiTop10IdSchema.safeParse("API11").success).toBe(false);
  });
});

describe("ASVS v4 chapters", () => {
  it("has the fourteen chapters", () => {
    expect(ASVS_V4_CHAPTERS).toHaveLength(14);
    expect(asvsChapter("V1")?.name).toBe("Architecture, Design and Threat Modeling");
    expect(asvsChapter("V4")?.name).toBe("Access Control");
    expect(asvsChapter("V14")?.name).toBe("Configuration");
    expect(AsvsChapterIdSchema.safeParse("V7").success).toBe(true);
    expect(AsvsChapterIdSchema.safeParse("V15").success).toBe(false);
  });
});

describe("CIS Controls v8", () => {
  it("has the eighteen controls", () => {
    expect(CIS_CONTROLS_V8).toHaveLength(18);
    expect(cisControl(7)?.name).toBe("Continuous Vulnerability Management");
    expect(cisControl(16)?.name).toBe("Application Software Security");
    expect(cisControl(18)?.name).toBe("Penetration Testing");
    expect(CisControlNumberSchema.safeParse(1).success).toBe(true);
    expect(CisControlNumberSchema.safeParse(19).success).toBe(false);
    expect(CisControlNumberSchema.safeParse(0).success).toBe(false);
  });
});

describe("mappingsForOwaspTop10", () => {
  it("names the ASVS chapters and CIS controls behind each category", () => {
    expect(mappingsForOwaspTop10("A01")).toEqual({ asvs: ["V4"], cis: [6, 16] });
    expect(mappingsForOwaspTop10("A07").asvs).toEqual(["V2", "V3"]);
    expect(mappingsForOwaspTop10("A09").asvs).toEqual(["V7"]);
    expect(mappingsForOwaspTop10("A09").cis).toEqual([8]);
  });
});

describe("lookupCwe", () => {
  it("maps the common web weaknesses to their OWASP category", () => {
    expect(lookupCwe(79)?.owaspTop10).toBe("A03"); // XSS
    expect(lookupCwe(89)?.owaspTop10).toBe("A03"); // SQL injection
    expect(lookupCwe(639)?.owaspTop10).toBe("A01"); // IDOR
    expect(lookupCwe(918)?.owaspTop10).toBe("A10"); // SSRF
    expect(lookupCwe(1021)?.owaspTop10).toBe("A04"); // clickjacking
    expect(lookupCwe(319)?.owaspTop10).toBe("A02"); // cleartext transmission
  });

  it("maps API weaknesses to the API Top 10 too", () => {
    expect(lookupCwe(639)?.owaspApi).toBe("API1");
    expect(lookupCwe(287)?.owaspApi).toBe("API2");
    expect(lookupCwe(770)?.owaspApi).toBe("API4");
    expect(lookupCwe(918)?.owaspApi).toBe("API7");
  });

  it("fills in ASVS and CIS from the OWASP category when the entry does not override them", () => {
    expect(lookupCwe(89)?.asvs).toEqual(["V5"]);
    expect(lookupCwe(89)?.cis).toEqual([16]);
    expect(lookupCwe(1004)?.asvs).toEqual(["V3"]); // cookie without HttpOnly: a session issue, not a generic misconfiguration
  });

  it("accepts the CWE-nnn spelling", () => {
    expect(lookupCwe("CWE-79")).toEqual(lookupCwe(79));
    expect(lookupCwe("cwe-79")).toEqual(lookupCwe(79));
  });

  it("returns undefined for a CWE it does not know", () => {
    expect(lookupCwe(999999)).toBeUndefined();
    expect(lookupCwe("not a cwe")).toBeUndefined();
  });

  it("covers a useful set of weaknesses", () => {
    const known = [20, 22, 78, 79, 89, 200, 287, 306, 307, 319, 326, 327, 352, 434, 502, 522, 532, 601, 611, 614, 639, 798, 862, 863, 918, 942, 1004, 1021];
    for (const id of known) expect(lookupCwe(id), `CWE-${id}`).toBeDefined();
  });
});
