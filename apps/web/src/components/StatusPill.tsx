import type { AssessmentStatus } from "@retest/schema";

/** One mark per row: the assessment's status as a pale pill, the one that is being worked on a step darker. */
export function StatusPill({ status }: { status: AssessmentStatus }) {
  return <span className={`pill${status === "active" ? " on" : ""}${status === "closed" ? " off" : ""}`}>{status}</span>;
}
