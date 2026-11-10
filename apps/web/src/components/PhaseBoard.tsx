import { PHASES, PHASE_DETAILS, type Phase } from "@retest/schema";
import type { Totals } from "../api/client.js";

/**
 * The six phases as one container split into six cells. The assessment sits in one of them (the
 * 2px rule in the one hue); each cell counts the findings that are in that phase, which is how
 * "33 in vulnerability assessment, 0 in validation" says that nothing has been verified yet.
 */
export function PhaseBoard({ current, totals }: { current: Phase; totals: Totals }) {
  return (
    <ol className="phases panel" aria-label="The six phases">
      {PHASES.map((phase) => {
        const d = PHASE_DETAILS[phase];
        const n = totals.byPhase[phase];
        const now = phase === current;
        return (
          <li key={phase} className="phase" aria-current={now ? "step" : undefined}>
            <div className="label">{d.label}</div>
            <div className={`value num${n === 0 ? " zero" : ""}`}>{n}</div>
            <div className="what">{now ? "The assessment is here. " : ""}{d.activity}</div>
          </li>
        );
      })}
    </ol>
  );
}
