import { describe, expect, it } from "vitest";
import { ASSESSMENT_STATUSES, AssessmentSchema, ScopeSchema } from "../src/assessment.js";

const lab = {
  id: "assessment-lab",
  name: "Juice Shop lab, November",
  scope: {
    targets: ["127.0.0.1:3000"],
    authorizedBy: "me, on my own machine",
  },
  createdAt: "2026-11-06T18:00:00Z",
  updatedAt: "2026-11-06T18:00:00Z",
};

describe("Scope", () => {
  it("needs at least one target and someone who authorised the work", () => {
    const s = ScopeSchema.parse(lab.scope);
    expect(s.exclusions).toEqual([]);
    expect(ScopeSchema.safeParse({ targets: [], authorizedBy: "x" }).success).toBe(false);
    expect(ScopeSchema.safeParse({ targets: ["127.0.0.1"] }).success).toBe(false);
    expect(ScopeSchema.safeParse({ targets: ["127.0.0.1"], authorizedBy: "" }).success).toBe(false);
  });

  it("rejects a window that ends before it starts", () => {
    const bad = { ...lab.scope, startsAt: "2026-11-10T00:00:00Z", endsAt: "2026-11-09T00:00:00Z" };
    expect(ScopeSchema.safeParse(bad).success).toBe(false);
    const good = { ...lab.scope, startsAt: "2026-11-09T00:00:00Z", endsAt: "2026-11-10T00:00:00Z" };
    expect(ScopeSchema.safeParse(good).success).toBe(true);
  });
});

describe("Assessment", () => {
  it("parses and starts in the scope phase as a draft", () => {
    const a = AssessmentSchema.parse(lab);
    expect(a.phase).toBe("scope");
    expect(a.status).toBe("draft");
    expect(a.client).toBeUndefined();
  });

  it("lists the statuses", () => {
    expect(ASSESSMENT_STATUSES).toEqual(["draft", "active", "closed"]);
  });

  it("rejects an unknown phase and an empty name", () => {
    expect(AssessmentSchema.safeParse({ ...lab, phase: "exploitation" }).success).toBe(false);
    expect(AssessmentSchema.safeParse({ ...lab, name: "" }).success).toBe(false);
  });
});
