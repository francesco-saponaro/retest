import { describe, expect, it } from "vitest";
import { count, findingLine, phaseLine, relativeDay, relativeTime, scopeLine, verifiedCount } from "../src/lib/format.js";
import { totalsOf } from "./fake.js";

describe("phaseLine", () => {
  it("says which of the six phases, with its label", () => {
    expect(phaseLine("scope")).toBe("1 of 6 · Scope and asset inventory");
    expect(phaseLine("assessment")).toBe("3 of 6 · Vulnerability assessment");
    expect(phaseLine("remediation")).toBe("6 of 6 · Remediation and retest");
  });
});

describe("relativeDay", () => {
  const now = new Date("2026-11-10T21:00:00Z");
  it("names today and yesterday, counts a week of days, then prints the date", () => {
    expect(relativeDay("2026-11-10T19:00:00Z", now)).toBe("today");
    expect(relativeDay("2026-11-09T23:30:00Z", now)).toBe("yesterday");
    expect(relativeDay("2026-11-07T10:00:00Z", now)).toBe("3 days ago");
    expect(relativeDay("2026-11-03T10:00:00Z", now)).toBe("7 days ago");
    expect(relativeDay("2026-11-02T10:00:00Z", now)).toBe("2026-11-02");
  });
});

describe("relativeTime", () => {
  const now = new Date("2026-11-10T21:00:00Z");
  it("adds the clock to today and yesterday and nothing to older dates", () => {
    expect(relativeTime("2026-11-10T19:52:00Z", now)).toMatch(/^today \d{2}:\d{2}$/);
    expect(relativeTime("2026-11-09T19:52:00Z", now)).toMatch(/^yesterday \d{2}:\d{2}$/);
    expect(relativeTime("2026-11-02T10:00:00Z", now)).toBe("2026-11-02");
  });
});

describe("verifiedCount", () => {
  it("counts the findings that reached validation or a later phase", () => {
    expect(verifiedCount(totalsOf({ recon: 4, assessment: 33 }))).toBe(0);
    expect(verifiedCount(totalsOf({ assessment: 30, validation: 5, risk: 1, remediation: 1 }))).toBe(7);
  });
});

describe("scopeLine", () => {
  it("counts the targets and exclusions and names the authorisation", () => {
    expect(scopeLine({ targets: ["127.0.0.1", "http://127.0.0.1:3000"], exclusions: [], authorizedBy: "francesco", authorizedAt: "2026-11-10T18:00:00Z" })).toBe(
      "2 targets, no exclusions · authorised by francesco on 2026-11-10",
    );
    expect(scopeLine({ targets: ["10.0.10.0/24"], exclusions: ["10.0.10.1"], authorizedBy: "ops" })).toBe("1 target, 1 exclusion · authorised by ops");
  });
});

describe("count", () => {
  it("puts the noun in the right number", () => {
    expect(count(0, "finding")).toBe("0 findings");
    expect(count(1, "finding")).toBe("1 finding");
    expect(count(37, "finding")).toBe("37 findings");
    expect(count(2, "import")).toBe("2 imports");
    expect(count(8, "entry")).toBe("8 entries");
    expect(count(1, "entry")).toBe("1 entry");
    expect(count(3, "day")).toBe("3 days");
  });
});

describe("findingLine", () => {
  it("says how much of the assessment is still only what a scanner said", () => {
    expect(findingLine(totalsOf({ recon: 4, assessment: 33 }, { assets: 5 }))).toBe(
      "37 findings on 5 assets, and all 37 are still what a scanner said: none has reached validation.",
    );
    expect(findingLine(totalsOf({ assessment: 30, validation: 5, risk: 2 }, { assets: 3 }))).toBe("37 findings on 3 assets; 7 verified, 30 still what a scanner said.");
    expect(findingLine(totalsOf({ validation: 1 }, { assets: 1 }))).toBe("1 finding on 1 asset; all of it verified.");
    expect(findingLine(totalsOf({}, { assets: 2 }))).toBe("No findings yet on 2 assets: nothing has been imported.");
    expect(findingLine(totalsOf({}))).toBe("No findings and no assets yet: nothing has been imported.");
  });
});
