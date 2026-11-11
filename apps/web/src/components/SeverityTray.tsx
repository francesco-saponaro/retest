import { SEVERITY_LABELS } from "@retest/schema";
import type { Totals } from "../api/client.js";
import { REPORT_ORDER } from "../lib/format.js";

/**
 * The findings by severity: five cells in one strip, and under them the whole as one bar of
 * parts in an ink ramp (critical darkest). The critical count is the only coloured number on the
 * screen, and only when it is not zero.
 */
export function SeverityTray({ totals }: { totals: Totals }) {
  const total = totals.findings;
  return (
    <div className="tray" role="group" aria-label="Findings by severity">
      <ul className="kpis">
        {REPORT_ORDER.map((s) => {
          const n = totals.bySeverity[s];
          return (
            <li key={s} className="kpi">
              <div className="label">{SEVERITY_LABELS[s]}</div>
              <div className={`value num${n === 0 ? " zero" : ""}${s === "critical" && n > 0 ? " critical" : ""}`}>{n}</div>
            </li>
          );
        })}
      </ul>
      {total > 0 ? (
        <div className="parts" aria-hidden="true">
          {REPORT_ORDER.filter((s) => totals.bySeverity[s] > 0).map((s) => (
            <span key={s} style={{ flexGrow: totals.bySeverity[s], background: `var(--sev-${s})` }} />
          ))}
        </div>
      ) : null}
    </div>
  );
}
