import { UNASSESSED_IMPACT, UNWRITTEN_FIX, type Finding, type FindingStatus, type RetestOutcome } from "./finding.js";
import { PHASES, PHASE_DETAILS, phaseNumber, type Phase } from "./phase.js";

/**
 * The rules a finding follows through the six phases and the four statuses. They are written as
 * questions with a reason for "no", so that the API can refuse with a sentence and a screen can
 * show the same sentence under a disabled button. Every rule here is one the roadmap states or
 * implies: a scanner suggests and a person verifies, so nothing is "validated" without proof a
 * person captured; a report needs the impact and the fix written; a finding is closed by the
 * retest, not by hand; and whatever moves backwards or is set aside says why.
 */
export type WorkflowFinding = Pick<Finding, "phase" | "status" | "evidence" | "impact" | "fix" | "retest">;

/** True when a text field holds something a person wrote, not the import's placeholder. */
export function isWritten(text: string): boolean {
  const t = text.trim();
  return t.length > 0 && t !== UNASSESSED_IMPACT && t !== UNWRITTEN_FIX;
}

/** Evidence a person captured, as opposed to a tool's output copied in by the import. */
export function personEvidence(f: Pick<Finding, "evidence">): Finding["evidence"] {
  return f.evidence.filter((e) => !e.source);
}

const STATUS_WORDS: Record<FindingStatus, string> = {
  open: "open",
  "false-positive": "a false positive",
  "accepted-risk": "an accepted risk",
  closed: "closed",
};

function notOpen(f: WorkflowFinding): string | null {
  if (f.status === "open") return null;
  const word = STATUS_WORDS[f.status];
  return f.status === "closed" ? "the finding is closed: the retest found it fixed; reopen it first" : `the finding is marked ${word}: reopen it first`;
}

/** Why a finding may not move to `to`, or null when it may. Moving back needs a reason. */
export function phaseChangeProblem(f: WorkflowFinding, to: Phase, reason?: string): string | null {
  if (f.phase === to) return null;
  const closed = notOpen(f);
  if (closed) return closed;
  const from = phaseNumber(f.phase);
  const target = phaseNumber(to);
  if (target < from) {
    return reason?.trim() ? null : `moving a finding back to ${PHASE_DETAILS[to].label.toLowerCase()} needs a reason`;
  }
  if (target > from + 1) {
    const next = PHASES[from] as Phase;
    return `phases are passed one phase at a time: ${PHASE_DETAILS[next].label.toLowerCase()} comes before ${PHASE_DETAILS[to].label.toLowerCase()}`;
  }
  switch (to) {
    case "validation":
      if (personEvidence(f).length === 0) return "validation needs evidence captured by a person: a scanner's output is a claim, not proof";
      return null;
    case "remediation":
      if (!isWritten(f.impact)) return "the impact has to be written before the fix is asked for";
      if (!isWritten(f.fix)) return "the fix has to be written before it is asked for: the owner needs to know what to change";
      return null;
    default:
      return null;
  }
}

function needsReason(reason: string | undefined, what: string): string | null {
  return reason?.trim() ? null : `${what} needs a reason`;
}

/** Why a finding may not take the status `to`, or null when it may. */
export function statusChangeProblem(f: WorkflowFinding, to: FindingStatus, reason?: string): string | null {
  if (f.status === to) return null;
  switch (to) {
    case "closed":
      return "a finding is closed by a retest that found it fixed, not by hand";
    case "open":
      return needsReason(reason, `reopening ${STATUS_WORDS[f.status] === "closed" ? "a closed finding" : STATUS_WORDS[f.status]}`);
    case "false-positive":
      if (f.status === "closed") return "the finding is closed: the retest found it fixed; reopen it first";
      return needsReason(reason, "marking a false positive");
    case "accepted-risk":
      if (f.status === "closed") return "the finding is closed: the retest found it fixed; reopen it first";
      if (phaseNumber(f.phase) < phaseNumber("risk")) return "a risk is accepted once the finding has been validated and rated: it is still in " + PHASE_DETAILS[f.phase].label.toLowerCase();
      return needsReason(reason, "accepting a risk");
  }
}

/** Why a retest with this outcome may not be recorded, or null when it may. */
export function retestProblem(f: WorkflowFinding, outcome: RetestOutcome): string | null {
  if (f.status === "false-positive") return "a false positive is not retested";
  if (f.status === "accepted-risk") return "an accepted risk is not retested: reopen it first";
  if (f.status === "closed") return "the finding is closed: the retest found it fixed; reopen it to test it again";
  if (f.phase !== "remediation") return `a retest is phase 6, remediation and retest: the finding is in ${PHASE_DETAILS[f.phase].label.toLowerCase()}, and the fix comes first`;
  if (outcome === "pending") return "a retest that has happened has a result: fixed, partially fixed or not fixed";
  return null;
}
