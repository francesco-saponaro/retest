import { describe, expect, it } from "vitest";
import { PHASES, PHASE_DETAILS, PhaseSchema, isPhaseAfter, nextPhase, phaseNumber, previousPhase } from "../src/phase.js";

describe("phase", () => {
  it("lists the six phases of an assessment in order", () => {
    expect(PHASES).toEqual(["scope", "recon", "assessment", "validation", "risk", "remediation"]);
  });

  it("numbers them 1 to 6", () => {
    expect(PHASES.map(phaseNumber)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it("describes each phase with its activity and its result", () => {
    expect(PHASE_DETAILS.scope.number).toBe(1);
    expect(PHASE_DETAILS.scope.label).toBe("Scope and asset inventory");
    expect(PHASE_DETAILS.validation.label).toBe("Validation / exploitation");
    expect(PHASE_DETAILS.remediation.label).toBe("Remediation and retest");
    for (const p of PHASES) {
      expect(PHASE_DETAILS[p].activity.length).toBeGreaterThan(0);
      expect(PHASE_DETAILS[p].result.length).toBeGreaterThan(0);
    }
  });

  it("validates a phase name", () => {
    expect(PhaseSchema.parse("recon")).toBe("recon");
    expect(PhaseSchema.safeParse("exploitation").success).toBe(false);
  });

  it("walks forward and backward and stops at the ends", () => {
    expect(nextPhase("scope")).toBe("recon");
    expect(nextPhase("risk")).toBe("remediation");
    expect(nextPhase("remediation")).toBeNull();
    expect(previousPhase("scope")).toBeNull();
    expect(previousPhase("validation")).toBe("assessment");
  });

  it("knows which phase comes later", () => {
    expect(isPhaseAfter("risk", "recon")).toBe(true);
    expect(isPhaseAfter("recon", "risk")).toBe(false);
    expect(isPhaseAfter("recon", "recon")).toBe(false);
  });
});
