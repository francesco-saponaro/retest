import { SEVERITY_LABELS, type Severity } from "@retest/schema";

/** The severity as a word with its step of the ink ramp beside it: the same ramp the overview's bar is drawn in. */
export function SeverityMark({ severity }: { severity: Severity }) {
  return (
    <span className="sev">
      <i aria-hidden="true" style={{ background: `var(--sev-${severity})` }} />
      {SEVERITY_LABELS[severity]}
    </span>
  );
}
