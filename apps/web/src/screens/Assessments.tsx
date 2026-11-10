import { useSuspenseQuery } from "@tanstack/react-query";
import { Link, useRouter, type ErrorComponentProps } from "@tanstack/react-router";
import { ApiError } from "../api/client.js";
import { StatusPill } from "../components/StatusPill.js";
import { PHASES, PHASE_DETAILS } from "@retest/schema";
import { count, messageOf, phaseLine, relativeDay } from "../lib/format.js";
import { assessmentsQuery } from "../queries.js";
import { assessmentsRoute } from "../router.js";

/** The one question here: which assessment needs me tonight? Each row says where it stands. */
export function Assessments() {
  const { client } = assessmentsRoute.useRouteContext();
  const { data: items } = useSuspenseQuery(assessmentsQuery(client));
  return (
    <>
      <Frame total={items.length} />
      <div className="with-rail">
      <div className="grid gap-6">
      <div className="panel">
        {items.length === 0 ? (
          <p className="empty">No assessments yet.</p>
        ) : (
          <div className="table-wrap">
            <table className="fold" aria-label="Assessments">
              <thead>
                <tr>
                  <th>Assessment</th>
                  <th>Phase</th>
                  <th>Status</th>
                  <th className="n">Targets</th>
                  <th className="n">Updated</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.id}>
                    <td className="id">
                      <Link to="/a/$id" params={{ id: a.id }}>
                        {a.name}
                      </Link>
                      {a.client ? <span className="sub">{a.client}</span> : null}
                    </td>
                    <td className="line2">{phaseLine(a.phase)}</td>
                    <td className="key">
                      <StatusPill status={a.status} />
                    </td>
                    <td className="n line2" data-unit={a.scope.targets.length === 1 ? "target" : "targets"}>
                      {a.scope.targets.length}
                    </td>
                    <td className="n line2 muted">{relativeDay(a.updatedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
        <ScannersPanel />
      </div>
      <PhasesRail />
      </div>
    </>
  );
}

/** The six scanners whose output an import reads, with what each one reports and the file it writes. */
const SCANNERS: { tool: string; reports: string; file: string }[] = [
  { tool: "Nmap", reports: "Hosts, open ports, services and versions; NSE script results such as vulners and SMB signing.", file: "XML (-oX)" },
  { tool: "Nuclei", reports: "Template matches on web endpoints: missing headers, CORS, exposed files, known CVEs.", file: "JSON Lines (-jsonl)" },
  { tool: "OWASP ZAP", reports: "Alerts from a baseline or active scan, with risk, confidence and the requests that triggered them.", file: "JSON report" },
  { tool: "Semgrep", reports: "Rule matches in source code with the file, the line and the snippet.", file: "SARIF" },
  { tool: "Trivy", reports: "Known vulnerabilities in a container image's packages, with the fixed version.", file: "JSON" },
  { tool: "Prowler", reports: "Failed cloud configuration checks against CIS benchmarks.", file: "OCSF JSON" },
];

function ScannersPanel() {
  return (
    <section aria-labelledby="scanners-heading">
      <header className="flex items-baseline justify-between gap-4 mb-3">
        <h2 id="scanners-heading" className="text-[18px] leading-6 font-medium">
          What an import reads
        </h2>
        <span className="note">six scanners, one finding format</span>
      </header>
      <div className="panel">
        <div className="table-wrap">
          <table className="fold">
            <thead>
              <tr>
                <th>Scanner</th>
                <th>Reports</th>
                <th className="n">File</th>
              </tr>
            </thead>
            <tbody>
              {SCANNERS.map((s) => (
                <tr key={s.tool}>
                  <td className="id whitespace-nowrap">{s.tool}</td>
                  <td className="line2 text-[13px]">{s.reports}</td>
                  <td className="n key muted whitespace-nowrap">{s.file}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

/** Beside the list, the process every assessment follows: the six phases and what each one leaves behind. */
function PhasesRail() {
  return (
    <aside className="rail" aria-labelledby="phases-heading">
      <header className="rail-header">
        <h2 id="phases-heading">The six phases</h2>
        <span className="note">what each one produces</span>
      </header>
      <ol className="panel steps">
        {PHASES.map((p) => (
          <li key={p}>
            <div className="label">{PHASE_DETAILS[p].label}</div>
            <div className="what">{PHASE_DETAILS[p].result}</div>
          </li>
        ))}
      </ol>
    </aside>
  );
}

function Frame({ total }: { total?: number }) {
  return (
    <div className="title-row">
      <div>
        <h1>Assessments</h1>
        <p className="sub">{total === undefined ? "Every engagement, with the phase its work is in." : total === 0 ? "Nothing authorised yet." : `${count(total, "assessment")}, each in one of the six phases.`}</p>
      </div>
    </div>
  );
}

/** The list could not be loaded: the frame stays, the failure sits where the table would be, with a retry. */
export function AssessmentsFailed({ error }: ErrorComponentProps) {
  const router = useRouter();
  const needsToken = error instanceof ApiError && error.status === 401;
  return (
    <>
      <Frame />
      <div className="panel">
        <div className="failed">
          <span>Couldn't load the assessments: {messageOf(error)}.</span>
          {needsToken ? (
            <Link to="/connect" className="btn">
              Connect
            </Link>
          ) : (
            <button type="button" className="btn" onClick={() => void router.invalidate()}>
              Retry
            </button>
          )}
        </div>
      </div>
    </>
  );
}
