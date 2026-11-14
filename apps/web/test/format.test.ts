import { describe, expect, it } from "vitest";
import { PHASES } from "@retest/schema";
import { auditSentence, count, findingLine, findingState, findingsLine, headline, historyLine, nextStep, phaseLine, relativeDay, relativeTime, scopeLine, shortPhase, verifiedCount } from "../src/lib/format.js";
import { totalsOf } from "./fake.js";
import { cors, detailOf, juiceFindings, jwt, login, manyFindings, summaryOf } from "./findings.js";

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

describe("shortPhase", () => {
  it("names each phase in one word", () => {
    expect(PHASES.map(shortPhase)).toEqual(["Scope", "Recon", "Assessment", "Validation", "Risk", "Remediation"]);
  });
});

describe("findingsLine", () => {
  const all = juiceFindings.map(summaryOf);
  it("counts what is shown, by severity, and whether any has been validated", () => {
    expect(findingsLine({ all: 6, matched: 6, items: all, filtered: false })).toBe("6 findings: 2 critical, 1 high, 2 medium; 1 verified.");
    expect(findingsLine({ all: 6, matched: 2, items: all.filter((f) => f.risk.severity === "critical"), filtered: true })).toBe("2 of 6 findings match: 2 critical; none has reached validation.");
  });
  it("says so when nothing is there, and why", () => {
    expect(findingsLine({ all: 0, matched: 0, items: [], filtered: false })).toBe("No findings yet: nothing has been imported.");
    expect(findingsLine({ all: 5, matched: 0, items: [], filtered: true })).toBe("0 of 5 findings match.");
  });
  it("counts the verified ones and says when the page is cut", () => {
    const verified = all.map((f, i) => ({ ...f, phase: i < 2 ? ("validation" as const) : f.phase }));
    expect(findingsLine({ all: 6, matched: 6, items: verified, filtered: false })).toBe("6 findings: 2 critical, 1 high, 2 medium; 3 verified.");
    expect(findingsLine({ all: 900, matched: 900, items: manyFindings(500), filtered: false })).toBe("The first 500 of 900 findings; narrow them with the filters.");
  });
});

describe("findingState", () => {
  const now = new Date("2026-11-10T21:00:00Z");
  it("says where the finding came from and whether anyone has looked at it", () => {
    expect(findingState(detailOf(jwt), now)).toMatch(/^Critical on bkimminich\/juice-shop:v17\.1\.1, reported by trivy today \d\d:\d\d\. Still what a scanner said: nobody has validated it\.$/);
    expect(findingState(detailOf(cors), now)).toMatch(/^Medium on http:\/\/127\.0\.0\.1:3000, reported by nuclei and zap today \d\d:\d\d\. Still what a scanner said: nobody has validated it\.$/);
    expect(findingState(detailOf({ ...login, phase: "validation" }), now)).toMatch(/Being validated\.$/);
    expect(findingState(detailOf({ ...login, phase: "remediation" }), now)).toMatch(/Validated; waiting on the fix and the retest\.$/);
    expect(findingState(detailOf({ ...login, status: "false-positive", falsePositiveReason: "test code" }), now)).toMatch(/Marked a false positive: test code\.$/);
    expect(findingState(detailOf({ ...login, status: "false-positive", falsePositiveReason: "Test code." }), now)).toMatch(/Marked a false positive: Test code\.$/);
  });
});

describe("headline", () => {
  it("keeps a short title, takes the part before a tool's colon, and otherwise cuts at a word", () => {
    expect(headline("CORS Misconfiguration: arbitrary-origin")).toBe("CORS Misconfiguration: arbitrary-origin");
    expect(headline("CVE-2015-9235 in jsonwebtoken 0.4.0: Verification Bypass in jsonwebtoken")).toBe("CVE-2015-9235 in jsonwebtoken 0.4.0");
    expect(headline("S3 Bucket juice-shop-uploads has public access due to bucket policy")).toBe("S3 Bucket juice-shop-uploads has public access due…");
    expect(headline("Security group lab-web (sg-0f3a9c1d2e4b5a6c7) has SSH port 22 open to the Internet")).toBe("Security group lab-web (sg-0f3a9c1d2e4b5a6c7) has…");
  });
});

describe("auditSentence", () => {
  const base = { id: 1, assessmentId: "a-1", actor: "francesco", at: "2026-11-14T18:00:00.000Z", reason: null, findingId: null };
  it("says what happened, in words, for each kind of line", () => {
    expect(auditSentence({ ...base, action: "import", field: "nmap", from: "nmap/juice-shop.xml", to: "4 parsed, 4 created, 0 merged" })).toBe("imported nmap/juice-shop.xml with nmap: 4 parsed, 4 created, 0 merged");
    expect(auditSentence({ ...base, action: "import", field: "zap", from: null, to: "6 parsed, 3 created, 3 merged" })).toBe("imported a zap file: 6 parsed, 3 created, 3 merged");
    expect(auditSentence({ ...base, action: "phase", field: "phase", from: "scope", to: "assessment" })).toBe("moved the assessment from scope and asset inventory to vulnerability assessment");
    expect(auditSentence({ ...base, action: "status", field: "status", from: "draft", to: "active" })).toBe("set the assessment active");
    expect(auditSentence({ ...base, findingId: "f-1", action: "phase", field: "phase", from: "assessment", to: "validation" })).toBe("moved it from vulnerability assessment to validation / exploitation");
    expect(auditSentence({ ...base, findingId: "f-1", action: "status", field: "status", from: "open", to: "false-positive" })).toBe("marked it a false positive");
    expect(auditSentence({ ...base, findingId: "f-1", action: "status", field: "status", from: "risk", to: "accepted-risk" })).toBe("accepted the risk");
    expect(auditSentence({ ...base, findingId: "f-1", action: "status", field: "status", from: "open", to: "closed" })).toBe("closed it");
    expect(auditSentence({ ...base, findingId: "f-1", action: "status", field: "status", from: "false-positive", to: "open" })).toBe("reopened it");
    expect(auditSentence({ ...base, findingId: "f-1", action: "retest", field: "retest", from: null, to: "not-fixed" })).toBe("retested it: not fixed");
    expect(auditSentence({ ...base, findingId: "f-1", action: "retest", field: "retest", from: "not-fixed", to: "fixed" })).toBe("retested it: fixed");
  });
});

describe("historyLine", () => {
  const base = { id: 1, assessmentId: "a-1", actor: "francesco", at: "2026-11-14T18:00:00.000Z", reason: null, findingId: null, field: "x", from: null, to: null };
  it("counts the entries by kind, newest first", () => {
    expect(historyLine([])).toBe("Nothing has happened yet.");
    expect(historyLine([{ ...base, action: "import" }])).toBe("1 entry: 1 import.");
    expect(
      historyLine([
        { ...base, action: "import" },
        { ...base, action: "import" },
        { ...base, action: "phase" },
        { ...base, action: "status" },
        { ...base, action: "retest" },
      ]),
    ).toBe("5 entries: 2 imports, 1 phase change, 1 status change, 1 retest; newest first.");
  });
});

describe("nextPhase and the step that follows", () => {
  it("names the move a finding can make next, or none at the end", () => {
    expect(nextStep("assessment")).toEqual({ phase: "validation", label: "Move to validation" });
    expect(nextStep("risk")).toEqual({ phase: "remediation", label: "Move to remediation and retest" });
    expect(nextStep("remediation")).toBeNull();
  });
});
