import { useQuery, useSuspenseQuery } from "@tanstack/react-query";
import { Link, useRouter, type ErrorComponentProps } from "@tanstack/react-router";
import { useState } from "react";
import { PHASES, PHASE_DETAILS, SEVERITIES, assetLabel, phaseNumber } from "@retest/schema";
import type { CoverageRow, Report as ReportModel, ReportFinding } from "@retest/api/report/model.js";
import { STATE_WORDS, verifiedLine } from "@retest/api/report/markdown.js";
import type { ApiClient, ReportKind } from "../api/client.js";
import { Crumbs } from "../components/Crumbs.js";
import { SeverityMark } from "../components/SeverityMark.js";
import { count, messageOf } from "../lib/format.js";
import { assessmentQuery, reportQuery } from "../queries.js";
import { reportRoute } from "../router.js";

/**
 * The two documents an assessment hands over, on one page that prints: the executive summary for
 * the people who decide, then the technical report for the people who fix. The question: can this
 * go to the client yet? The answer is the number of serious findings nobody has verified, said
 * first. The page renders the same report model as the API's markdown, so the PDF and the markdown
 * files say the same thing.
 */
export function Report() {
  const { client } = reportRoute.useRouteContext();
  const { id } = reportRoute.useParams();
  const { data: a } = useSuspenseQuery(assessmentQuery(client, id));
  const report = useQuery(reportQuery(client, id));

  return (
    <>
      <div className="title-row report-head">
        <div>
          <Crumbs>
            <Link to="/" className="crumb">
              Assessments
            </Link>
            <Link to="/a/$id" params={{ id }} className="crumb">
              {a.name}
            </Link>
          </Crumbs>
          <h1>Report</h1>
          <p className="sub">{report.data ? reportLine(report.data) : "Writing the report from the findings."}</p>
        </div>
        <Actions client={client} id={id} name={a.name} ready={report.isSuccess} />
      </div>

      {report.isPending ? (
        <div className="panel paper" aria-busy="true">
          {Array.from({ length: 6 }, (_, i) => (
            <span key={i} className="skeleton block h-4 my-4" style={{ width: `${80 - i * 8}%` }} />
          ))}
        </div>
      ) : report.isError ? (
        <div className="panel">
          <div className="failed">
            <span>Couldn't write the report: {report.error.message}.</span>
            <button type="button" className="btn" onClick={() => void report.refetch()}>
              Retry
            </button>
          </div>
        </div>
      ) : (
        <Paper id={id} report={report.data} />
      )}
    </>
  );
}

function reportLine(r: ReportModel): string {
  return `${count(r.counts.findings, "finding")} on ${count(r.counts.assets, "asset")}, ${r.counts.verified} verified by a person. Generated ${r.generatedAt.slice(0, 10)}.`;
}

function slug(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "assessment";
}

/** Save the markdown the API renders as a file, and print the page for a PDF. */
function Actions({ client, id, name, ready }: { client: ApiClient; id: string; name: string; ready: boolean }) {
  const [failed, setFailed] = useState<string | null>(null);
  const download = async (kind: ReportKind) => {
    setFailed(null);
    try {
      const text = await client.getReportMarkdown(id, kind);
      const url = URL.createObjectURL(new Blob([text], { type: "text/markdown;charset=utf-8" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `${slug(name)}-${kind}.md`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setFailed(messageOf(e));
    }
  };
  return (
    <div className="report-actions">
      <div className="report-buttons">
        <button type="button" className="btn" disabled={!ready} onClick={() => void download("summary")}>
          Summary .md
        </button>
        <button type="button" className="btn" disabled={!ready} onClick={() => void download("report")}>
          Technical report .md
        </button>
        <button type="button" className="btn primary" disabled={!ready} onClick={() => window.print()}>
          Print or save as PDF
        </button>
      </div>
      {failed ? (
        <p className="error-line" role="alert">
          Couldn't download it: {failed}.
        </p>
      ) : null}
    </div>
  );
}

function Paper({ id, report }: { id: string; report: ReportModel }) {
  const a = report.assessment;
  const scope = a.scope;
  return (
    <article className="panel paper" aria-label="Report">
      <header className="paper-head">
        <h2>{a.name}</h2>
        <p className="doc-kind">Vulnerability assessment: executive summary and technical report</p>
        <dl className="facts">
          {a.client ? (
            <div>
              <dt>Client</dt>
              <dd>{a.client}</dd>
            </div>
          ) : null}
          <div>
            <dt>Authorised by</dt>
            <dd>
              {scope.authorizedBy}
              {scope.authorizedAt ? ` on ${scope.authorizedAt.slice(0, 10)}` : ""}
            </dd>
          </div>
          <div>
            <dt>Targets</dt>
            <dd>{scope.targets.join(", ")}</dd>
          </div>
          {scope.exclusions.length ? (
            <div>
              <dt>Excluded</dt>
              <dd>{scope.exclusions.join(", ")}</dd>
            </div>
          ) : null}
          <div>
            <dt>Generated</dt>
            <dd>{report.generatedAt.slice(0, 10)}</dd>
          </div>
        </dl>
      </header>
      <Summary id={id} report={report} />
      <Technical id={id} report={report} />
    </article>
  );
}

function Summary({ id, report }: { id: string; report: ReportModel }) {
  const c = report.counts;
  const a = report.assessment;
  const notTested = report.coverage.owasp.filter((r) => r.state === "not-tested");
  return (
    <section className="part" aria-labelledby="summary-heading">
      <h2 id="summary-heading" className="part-title">
        Executive summary
      </h2>
      <p className="lead">
        {count(c.findings, "finding")} on {count(c.assets, "asset")}: {c.open} open, {c.closed} closed, {count(c.falsePositive, "false positive")}, {c.acceptedRisk} accepted. <strong>{c.verified} of {c.findings}</strong> verified by a person. Phase {phaseNumber(a.phase)} of 6, {PHASE_DETAILS[a.phase].label.toLowerCase()}.
      </p>
      {report.unverifiedSerious ? (
        <p className="callout">
          <strong>
            {report.unverifiedSerious} high or critical {report.unverifiedSerious === 1 ? "finding is" : "findings are"} still a scanner's claim.
          </strong>{" "}
          Read {report.unverifiedSerious === 1 ? "it" : "them"} as "to be checked", not as proven.{" "}
          <Link to="/a/$id/findings" params={{ id }} className="crumb no-print">
            Open the findings
          </Link>
        </p>
      ) : null}

      <div className="paper-two">
        <div>
          <h3>By severity</h3>
          <table className="plain" aria-label="Findings by severity">
            <tbody>
              {[...SEVERITIES].reverse().map((s) => (
                <tr key={s}>
                  <td>
                    <SeverityMark severity={s} />
                  </td>
                  <td className="n num">{c.bySeverity[s]}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="quiet-note">False positives left out.</p>
        </div>
        <div>
          <h3>By phase</h3>
          <table className="plain" aria-label="Findings by phase">
            <tbody>
              {PHASES.map((p) => (
                <tr key={p}>
                  <td>
                    {phaseNumber(p)}. {PHASE_DETAILS[p].label}
                  </td>
                  <td className="n num">{c.byPhase[p]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <h3>Top risks</h3>
      {report.topRisks.length ? (
        <ol className="risks">
          {report.topRisks.map((f) => (
            <li key={f.id}>
              <Link to="/a/$id/findings/$fid" params={{ id, fid: f.id }} className="risk-title">
                {f.title}
              </Link>
              <span className="risk-facts">
                <SeverityMark severity={f.risk.severity} />
                {f.risk.cvss ? <span className="num">{f.risk.cvss.baseScore}</span> : null}
                <span className={f.verified ? "verified" : "unverified"}>{f.verified ? "Verified" : "Not verified"}</span>
                {f.risk.likelihood && f.risk.impact ? (
                  <span>
                    Business risk: likelihood {f.risk.likelihood}, impact {f.risk.impact}
                  </span>
                ) : null}
              </span>
              <span className="risk-where">
                {assetName(report, f.assetId)}, {f.scope}
              </span>
            </li>
          ))}
        </ol>
      ) : (
        <p className="quiet-note">No open finding above informational.</p>
      )}

      <h3>Severity and business risk</h3>
      <p className="body-text">
        Severity here is the CVSS base score: how bad the flaw is anywhere it appears. It does not know what the asset holds or who can reach it. Where the assessor has rated likelihood and impact for this business, the top risks show both, and that is the order to fix in.
      </p>

      <h3>Trend</h3>
      {report.trend.length ? (
        <div className="table-wrap">
          <table className="plain trend" aria-label="Trend by day">
            <thead>
              <tr>
                <th>Day</th>
                <th className="n">Found</th>
                <th className="n">Closed</th>
                <th className="n">Set aside</th>
                <th className="n">Reopened</th>
                <th className="n">Open at end of day</th>
              </tr>
            </thead>
            <tbody>
              {report.trend.map((d) => (
                <tr key={d.day}>
                  <td className="num">{d.day}</td>
                  <td className="n num">{d.found}</td>
                  <td className="n num">{d.closed}</td>
                  <td className="n num">{d.setAside}</td>
                  <td className="n num">{d.reopened}</td>
                  <td className="n num strong">{d.open}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="quiet-note">Nothing imported yet.</p>
      )}

      <h3>Coverage</h3>
      <p className="body-text">
        {10 - notTested.length} of the 10 OWASP Top 10 categories were looked at by the tools that ran ({report.coverage.toolsRun.join(", ") || "none"}).
        {notTested.length ? ` Not tested: ${notTested.map((r) => `${r.id} ${r.name}`).join(", ")}.` : ""} An empty category is not a clean bill of health; the matrix at the end of the technical report has every row.
      </p>
    </section>
  );
}

function assetName(report: ReportModel, assetId: string): string {
  const asset = report.groups.find((g) => g.asset.id === assetId)?.asset;
  return asset ? assetLabel(asset) : assetId;
}

function Technical({ id, report }: { id: string; report: ReportModel }) {
  return (
    <section className="part" aria-labelledby="technical-heading">
      <h2 id="technical-heading" className="part-title">
        Technical report
      </h2>
      <p className="lead">One section per asset, one entry per finding, most severe first. Evidence is shown only once it has been redacted.</p>
      {report.groups.map((g) => (
        <section key={g.asset.id} className="asset-group" aria-label={assetLabel(g.asset)}>
          <h3 className="asset-title">
            {assetLabel(g.asset)}
            <span className="quiet-note">
              {" "}
              {g.asset.kind}
              {g.asset.inScope ? "" : ", recorded as out of scope"}, {count(g.findings.length, "finding")}
            </span>
          </h3>
          {g.findings.map((f) => (
            <FindingEntry key={f.id} id={id} f={f} />
          ))}
        </section>
      ))}
      <h3 className="asset-title">Coverage</h3>
      <p className="body-text">A category counts as looked at when a tool that has rules for it ran: some of its issues were checked, not all. No scanner tests A04 Insecure Design.</p>
      <CoverageTable label="OWASP Top 10 2021" rows={report.coverage.owasp} lookedHeader="Looked for by" />
      <p className="body-text">A scanner can show an ASVS requirement failing; it cannot show a chapter passing. A chapter with no finding has not been verified, only not failed.</p>
      <CoverageTable label="ASVS 4.0.3 chapters" rows={report.coverage.asvs} lookedHeader="Found by" />
    </section>
  );
}

function FindingEntry({ id, f }: { id: string; f: ReportFinding }) {
  const shown = f.evidence.filter((e) => e.redacted);
  const held = f.evidence.length - shown.length;
  return (
    <article className="entry" aria-label={f.title}>
      <h4>
        <Link to="/a/$id/findings/$fid" params={{ id, fid: f.id }}>
          {f.title}
        </Link>
      </h4>
      <p className={`check ${f.verified ? "verified" : "unverified"}`}>{verifiedLine(f)}</p>
      <dl className="entry-fields">
        <div>
          <dt>Asset and scope</dt>
          <dd>{f.scope}</dd>
        </div>
        <div>
          <dt>Impact</dt>
          <dd className="prose">{f.impact}</dd>
        </div>
        <div>
          <dt>Evidence</dt>
          <dd>
            {shown.map((e) => (
              <figure key={e.id} className="ev">
                <figcaption>
                  {e.title ? `${e.title} ` : ""}({e.kind})
                </figcaption>
                <pre>{e.content}</pre>
              </figure>
            ))}
            {held ? <span className="quiet-note">{count(held, "piece")} of evidence not yet redacted, not shown.</span> : null}
            {!f.evidence.length ? <span className="quiet-note">None recorded.</span> : null}
          </dd>
        </div>
        <div>
          <dt>Risk</dt>
          <dd>
            <SeverityMark severity={f.risk.severity} />
            {f.risk.cvss ? (
              <span className="vector">
                {" "}
                CVSS <span className="num">{f.risk.cvss.baseScore}</span> {f.risk.cvss.vector}
              </span>
            ) : null}
          </dd>
        </div>
        <div>
          <dt>Fix</dt>
          <dd className="prose">{f.fix}</dd>
        </div>
        <div>
          <dt>Retest</dt>
          <dd>{f.retest ? `${f.retest.outcome}${f.retest.testedAt ? ` on ${f.retest.testedAt.slice(0, 10)}` : ""}${f.retest.notes ? `: ${f.retest.notes}` : ""}` : "Not retested yet."}</dd>
        </div>
      </dl>
      <p className="entry-meta">
        Phase {phaseNumber(f.phase)} ({PHASE_DETAILS[f.phase].label.toLowerCase()}), {f.status}. Sources: {f.sources.map((s) => s.tool).join(", ")}.
        {f.mappings.owaspTop10.length ? ` OWASP ${f.mappings.owaspTop10.join(", ")}.` : ""}
        {f.mappings.cve.length ? ` ${f.mappings.cve.join(", ")}.` : ""}
      </p>
    </article>
  );
}

function CoverageTable({ label, rows, lookedHeader }: { label: string; rows: CoverageRow[]; lookedHeader: string }) {
  return (
    <div className="table-wrap coverage-wrap">
      <table className="plain coverage" aria-label={label}>
        <caption>{label}</caption>
        <thead>
          <tr>
            <th>Category</th>
            <th className="n">Findings</th>
            <th className="n">Open</th>
            <th className="n">Verified</th>
            <th>{lookedHeader}</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className={`state-${r.state}`}>
              <td>
                <span className="num cat-id">{r.id}</span> {r.name}
              </td>
              <td className="n num">{r.findings}</td>
              <td className="n num">{r.open}</td>
              <td className="n num">{r.verified}</td>
              <td>{r.lookedBy.length ? r.lookedBy.join(", ") : <span className="dash">none</span>}</td>
              <td className="result-cell">{STATE_WORDS[r.state]}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ReportFailed({ error }: ErrorComponentProps) {
  const router = useRouter();
  const { id } = reportRoute.useParams();
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
          <h1>Report</h1>
        </div>
      </div>
      <div className="panel">
        <div className="failed">
          <span>Couldn't load the report: {messageOf(error)}.</span>
          <button type="button" className="btn" onClick={() => void router.invalidate()}>
            Retry
          </button>
        </div>
      </div>
    </>
  );
}
