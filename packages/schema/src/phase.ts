import { z } from "zod";

/** The six phases of an assessment, in order. An assessment and every finding in it sit in exactly one. */
export const PHASES = ["scope", "recon", "assessment", "validation", "risk", "remediation"] as const;

export const PhaseSchema = z.enum(PHASES);
export type Phase = z.infer<typeof PhaseSchema>;

export interface PhaseDetails {
  /** 1 to 6. */
  number: number;
  label: string;
  /** What is done in this phase. */
  activity: string;
  /** What the phase has produced when it is over. */
  result: string;
}

export const PHASE_DETAILS: Record<Phase, PhaseDetails> = {
  scope: {
    number: 1,
    label: "Scope and asset inventory",
    activity: "Agree what may be tested, by whom, when, and what is excluded. List the assets.",
    result: "A written authorisation, the targets, the exclusions and the systems to test.",
  },
  recon: {
    number: 2,
    label: "Reconnaissance and discovery",
    activity: "Find out what is actually there: hosts, open ports, services, endpoints and technologies.",
    result: "An inventory of hosts, ports, services, endpoints and the software behind them.",
  },
  assessment: {
    number: 3,
    label: "Vulnerability assessment",
    activity: "Run scanners and checks against the inventory to find potential problems.",
    result: "A list of candidate issues, each tied to an asset, none of them confirmed yet.",
  },
  validation: {
    number: 4,
    label: "Validation / exploitation",
    activity: "Confirm each candidate with a controlled, non-destructive test and keep the proof.",
    result: "Confirmed findings with evidence, and the false positives marked as such.",
  },
  risk: {
    number: 5,
    label: "Risk assessment and report",
    activity: "Rate each confirmed finding by likelihood and impact, score it, and write it up.",
    result: "Evidence, impact, likelihood and priority for every finding, in a report.",
  },
  remediation: {
    number: 6,
    label: "Remediation and retest",
    activity: "The owner fixes or updates; the assessor tests again.",
    result: "A fix, and the outcome of the retest after it.",
  },
};

export function phaseNumber(phase: Phase): number {
  return PHASES.indexOf(phase) + 1;
}

export function nextPhase(phase: Phase): Phase | null {
  const i = PHASES.indexOf(phase);
  return PHASES[i + 1] ?? null;
}

export function previousPhase(phase: Phase): Phase | null {
  const i = PHASES.indexOf(phase);
  return i > 0 ? (PHASES[i - 1] ?? null) : null;
}

/** True when a comes strictly later than b. */
export function isPhaseAfter(a: Phase, b: Phase): boolean {
  return PHASES.indexOf(a) > PHASES.indexOf(b);
}
