import { useQuery, useSuspenseQuery } from "@tanstack/react-query";
import { Link, useRouter, type ErrorComponentProps } from "@tanstack/react-router";
import type { AuditLine, FindingSummary } from "../api/client.js";
import { Crumbs } from "../components/Crumbs.js";
import { auditSentence, historyLine, messageOf, relativeTime } from "../lib/format.js";
import { assessmentQuery, auditQuery, findingsQuery } from "../queries.js";
import { auditRoute } from "../router.js";

/**
 * Everything that happened to an assessment, newest first: imports, the assessment's own phase and
 * status, and every move of every finding, with who did it and the reason given. The question: who
 * decided what, and when? Nothing here is ever edited or deleted; the API only appends.
 */
export function History() {
  const { client } = auditRoute.useRouteContext();
  const { id } = auditRoute.useParams();
  const { data: a } = useSuspenseQuery(assessmentQuery(client, id));
  const lines = useQuery(auditQuery(client, id));
  const findings = useQuery(findingsQuery(client, id, {}));
  const titles = new Map((findings.data?.items ?? []).map((f) => [f.id, f.title]));

  return (
    <>
      <div className="title-row">
        <div>
          <Crumbs>
            <Link to="/" className="crumb">
              Assessments
            </Link>
            <Link to="/a/$id" params={{ id }} className="crumb">
              {a.name}
            </Link>
          </Crumbs>
          <h1>History</h1>
          <p className="sub">{lines.data ? historyLine(lines.data) : "Loading the history."}</p>
        </div>
      </div>

      <section className="section" style={{ marginTop: 0 }} aria-labelledby="history-heading">
        <header>
          <h2 id="history-heading">Every entry</h2>
          <span className="note">who, when, what, and why</span>
        </header>
        {lines.isPending ? (
          <div className="panel" aria-busy="true">
            {Array.from({ length: 5 }, (_, i) => (
              <div key={i} className="flex items-center gap-3 px-5" style={{ height: "var(--row-height)" }}>
                <span className="skeleton h-4 w-24" />
                <span className="skeleton h-4 w-64" />
              </div>
            ))}
          </div>
        ) : lines.isError ? (
          <div className="panel">
            <div className="failed">
              <span>Couldn't load the history: {lines.error.message}.</span>
              <button type="button" className="btn" onClick={() => void lines.refetch()}>
                Retry
              </button>
            </div>
          </div>
        ) : lines.data.length === 0 ? (
          <div className="panel">
            <p className="empty">Nothing has happened to this assessment yet: no import, no change of phase.</p>
          </div>
        ) : (
          <div className="panel">
            <HistoryTable id={id} lines={lines.data} titles={titles} findings={findings.data?.items} />
          </div>
        )}
      </section>
    </>
  );
}

function HistoryTable({ id, lines, titles, findings }: { id: string; lines: AuditLine[]; titles: Map<string, string>; findings: FindingSummary[] | undefined }) {
  return (
    <div className="table-wrap">
      <table className="fold history-table" aria-label="History">
        <thead>
          <tr>
            <th>When</th>
            <th>Who</th>
            <th>What</th>
            <th>Why</th>
          </tr>
        </thead>
        <tbody>
          {[...lines].reverse().map((l) => (
            <tr key={l.id}>
              <td className="id whitespace-nowrap">{relativeTime(l.at)}</td>
              <td className="line2">{l.actor}</td>
              <td className="key">
                {l.findingId ? (
                  <>
                    <Link to="/a/$id/findings/$fid" params={{ id, fid: l.findingId }} className="crumb">
                      {titles.get(l.findingId) ?? (findings ? l.findingId : "…")}
                    </Link>
                    <span className="block">{auditSentence(l)}</span>
                  </>
                ) : (
                  auditSentence(l)
                )}
              </td>
              <td className={`line2${l.reason ? "" : " quiet"}`}>{l.reason ?? <span className="dash">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function HistoryFailed({ error }: ErrorComponentProps) {
  const router = useRouter();
  const { id } = auditRoute.useParams();
  return (
    <>
      <div className="title-row">
        <div>
          <Crumbs>
            <Link to="/" className="crumb">
              Assessments
            </Link>
            <Link to="/a/$id" params={{ id }} className="crumb">
              Assessment
            </Link>
          </Crumbs>
          <h1>History</h1>
        </div>
      </div>
      <div className="panel">
        <div className="failed">
          <span>Couldn't load the history: {messageOf(error)}.</span>
          <button type="button" className="btn" onClick={() => void router.invalidate()}>
            Retry
          </button>
        </div>
      </div>
    </>
  );
}
