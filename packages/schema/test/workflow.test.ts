import { describe, expect, it } from "vitest";
import { UNASSESSED_IMPACT, UNWRITTEN_FIX, newFinding, type Finding } from "../src/finding.js";
import { isWritten, phaseChangeProblem, retestProblem, statusChangeProblem } from "../src/workflow.js";

/** A finding as an import leaves it: a scanner's claim, the impact and the fix still placeholders, the tool's output as evidence. */
function imported(over: Partial<Finding> = {}): Finding {
  return newFinding({
    id: "f-cors",
    assessmentId: "a-lab",
    title: "CORS Misconfiguration: arbitrary-origin",
    assetId: "asset-web-127-0-0-1-3000",
    scope: "GET /rest/products/search?q=",
    impact: UNASSESSED_IMPACT,
    fix: UNWRITTEN_FIX,
    risk: { severity: "medium" },
    phase: "assessment",
    sources: [{ tool: "nuclei", rawId: "cors-misconfig:arbitrary-origin" }],
    evidence: [{ id: "f-cors-e1", kind: "request-response", content: "GET /rest/products/search?q= HTTP/1.1\nOrigin: https://example.com\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *", source: { tool: "nuclei", rawId: "cors-misconfig:arbitrary-origin" } }],
    ...over,
  });
}

const proof = { id: "ev-1", kind: "command-output" as const, content: "$ curl -si -H 'Origin: https://evil.example' http://127.0.0.1:3000/rest/user/whoami | grep -i access-control\nAccess-Control-Allow-Origin: *", redacted: true };

describe("isWritten", () => {
  it("is false while a field still holds the import's placeholder", () => {
    expect(isWritten(UNASSESSED_IMPACT)).toBe(false);
    expect(isWritten(UNWRITTEN_FIX)).toBe(false);
    expect(isWritten("Any website can read these three endpoints from a visitor's browser.")).toBe(true);
    expect(isWritten("   ")).toBe(false);
  });
});

describe("phaseChangeProblem", () => {
  it("lets a finding stay where it is", () => {
    expect(phaseChangeProblem(imported(), "assessment")).toBeNull();
  });

  it("moves one phase forward at a time", () => {
    expect(phaseChangeProblem(imported({ phase: "recon" }), "assessment")).toBeNull();
    expect(phaseChangeProblem(imported({ phase: "recon" }), "validation")).toMatch(/one phase at a time/);
    expect(phaseChangeProblem(imported({ phase: "assessment" }), "risk")).toMatch(/one phase at a time/);
  });

  it("refuses validation without evidence a person captured", () => {
    expect(phaseChangeProblem(imported(), "validation")).toMatch(/evidence captured by a person/);
    expect(phaseChangeProblem(imported({ evidence: [] }), "validation")).toMatch(/evidence captured by a person/);
    expect(phaseChangeProblem(imported({ evidence: [...imported().evidence, proof] }), "validation")).toBeNull();
  });

  it("refuses remediation until the impact and the fix are written", () => {
    const validated = imported({ phase: "risk", evidence: [proof] });
    expect(phaseChangeProblem(validated, "remediation")).toMatch(/impact/);
    expect(phaseChangeProblem(imported({ phase: "risk", evidence: [proof], impact: "Public data is readable cross-origin." }), "remediation")).toMatch(/fix/);
    expect(phaseChangeProblem(imported({ phase: "risk", evidence: [proof], impact: "Public data is readable cross-origin.", fix: "Echo only allowed origins." }), "remediation")).toBeNull();
  });

  it("lets a finding move back, with a reason", () => {
    const rated = imported({ phase: "risk", evidence: [proof] });
    expect(phaseChangeProblem(rated, "validation")).toMatch(/reason/);
    expect(phaseChangeProblem(rated, "validation", "The capture was of the wrong endpoint.")).toBeNull();
    expect(phaseChangeProblem(rated, "assessment", "Start again.")).toBeNull();
  });

  it("does not move a finding that is not open", () => {
    expect(phaseChangeProblem(imported({ status: "false-positive", falsePositiveReason: "A timestamp in minified JS." }), "validation")).toMatch(/false positive/);
    expect(phaseChangeProblem(imported({ phase: "remediation", status: "closed", retest: { outcome: "fixed", testedAt: "2026-11-14T18:00:00Z" } }), "risk", "x")).toMatch(/closed/);
    expect(phaseChangeProblem(imported({ phase: "risk", status: "accepted-risk" }), "remediation")).toMatch(/accepted/);
  });
});

describe("statusChangeProblem", () => {
  it("needs a reason to mark a false positive, and takes one from any open phase", () => {
    expect(statusChangeProblem(imported(), "false-positive")).toMatch(/reason/);
    expect(statusChangeProblem(imported(), "false-positive", "The ten digits are a build id, not a timestamp.")).toBeNull();
    expect(statusChangeProblem(imported({ phase: "recon" }), "false-positive", "Not a service: a banner from the proxy.")).toBeNull();
  });

  it("accepts a risk only once it has been rated, with a reason", () => {
    expect(statusChangeProblem(imported(), "accepted-risk", "Internal only.")).toMatch(/rated/);
    expect(statusChangeProblem(imported({ phase: "risk", evidence: [proof] }), "accepted-risk")).toMatch(/reason/);
    expect(statusChangeProblem(imported({ phase: "risk", evidence: [proof] }), "accepted-risk", "The endpoints return public data only; revisit if that changes.")).toBeNull();
    expect(statusChangeProblem(imported({ phase: "remediation", evidence: [proof] }), "accepted-risk", "Fix scheduled for next quarter.")).toBeNull();
  });

  it("never closes by hand", () => {
    expect(statusChangeProblem(imported({ phase: "remediation" }), "closed")).toMatch(/retest/);
  });

  it("reopens a false positive, an accepted risk or a closed finding with a reason", () => {
    const fp = imported({ status: "false-positive", falsePositiveReason: "A build id." });
    expect(statusChangeProblem(fp, "open")).toMatch(/reason/);
    expect(statusChangeProblem(fp, "open", "It is a timestamp after all: it changes on every build.")).toBeNull();
    const closed = imported({ phase: "remediation", status: "closed", retest: { outcome: "fixed", testedAt: "2026-11-14T18:00:00Z" } });
    expect(statusChangeProblem(closed, "open", "Regressed in 17.2.0.")).toBeNull();
    expect(statusChangeProblem(imported({ phase: "risk", status: "accepted-risk" }), "open", "The data is private now.")).toBeNull();
  });

  it("does not turn a closed finding into a false positive or an accepted risk", () => {
    const closed = imported({ phase: "remediation", status: "closed", retest: { outcome: "fixed", testedAt: "2026-11-14T18:00:00Z" } });
    expect(statusChangeProblem(closed, "false-positive", "x")).toMatch(/reopen/);
    expect(statusChangeProblem(closed, "accepted-risk", "x")).toMatch(/reopen/);
  });

  it("is a no-op for the status it already has", () => {
    expect(statusChangeProblem(imported(), "open")).toBeNull();
  });
});

describe("retestProblem", () => {
  const awaiting = imported({ phase: "remediation", evidence: [proof], impact: "Public data readable.", fix: "Echo allowed origins only." });

  it("is for an open finding in remediation only", () => {
    expect(retestProblem(awaiting, "fixed")).toBeNull();
    expect(retestProblem(imported({ phase: "risk" }), "fixed")).toMatch(/remediation/);
    expect(retestProblem(imported(), "not-fixed")).toMatch(/remediation/);
  });

  it("refuses a pending outcome: a retest that happened has a result", () => {
    expect(retestProblem(awaiting, "pending")).toMatch(/result/);
  });

  it("is not for a false positive, an accepted risk or a finding already closed", () => {
    expect(retestProblem({ ...awaiting, status: "false-positive" }, "fixed")).toMatch(/false positive/);
    expect(retestProblem({ ...awaiting, status: "accepted-risk" }, "fixed")).toMatch(/accepted/);
    expect(retestProblem({ ...awaiting, status: "closed", retest: { outcome: "fixed", testedAt: "2026-11-14T18:00:00Z" } }, "not-fixed")).toMatch(/reopen/);
  });

  it("lets a not-fixed finding be tested again", () => {
    expect(retestProblem({ ...awaiting, retest: { outcome: "not-fixed", testedAt: "2026-11-14T18:00:00Z" } }, "fixed")).toBeNull();
  });
});
