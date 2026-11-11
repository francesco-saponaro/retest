import { useMutation, useQueryClient, useSuspenseQuery } from "@tanstack/react-query";
import { Link, useRouter, type ErrorComponentProps } from "@tanstack/react-router";
import { FINDING_FIELDS, asvsChapter, owaspApiTop10, owaspTop10, type Evidence, type FindingFieldKey, type Source } from "@retest/schema";
import { UNASSESSED_IMPACT, UNWRITTEN_FIX } from "@retest/parsers";
import type { ReactNode } from "react";
import type { FindingDetail } from "../api/client.js";
import { Crumbs } from "../components/Crumbs.js";
import { CvssCalculator } from "../components/CvssCalculator.js";
import { SeverityMark } from "../components/SeverityMark.js";
import { EVIDENCE_KIND_LABELS, redactionLine, secretLines, splitRequestResponse } from "../lib/evidence.js";
import { count, findingState, headline, isoDate, messageOf, relativeTime } from "../lib/format.js";
import { assessmentQuery, findingQuery } from "../queries.js";
import { findingRoute } from "../router.js";

const KIND_LABELS: Record<FindingDetail["asset"]["kind"], string> = {
  host: "host",
  service: "service",
  "web-app": "web app",
  api: "API",
  repository: "repository",
  "container-image": "container image",
  "cloud-account": "cloud account",
  "cloud-resource": "cloud resource",
};

/**
 * One finding, the way the roadmap asks for it: the seven fields in order, then the proof, then
 * the risk worked out from a vector, then where it came from. The question: is this real, and is
 * it written so that a developer can act on it? The fields a tool cannot write say so themselves.
 */
export function Finding() {
  const { client } = findingRoute.useRouteContext();
  const { id, fid } = findingRoute.useParams();
  const { data: a } = useSuspenseQuery(assessmentQuery(client, id));
  const { data: f } = useSuspenseQuery(findingQuery(client, fid));
  const queryClient = useQueryClient();
  const store = useMutation({
    mutationFn: (risk: FindingDetail["risk"]) => client.updateFinding(fid, { risk }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["findings", fid] });
      await queryClient.invalidateQueries({ queryKey: ["assessments", id] });
    },
  });

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
            <Link to="/a/$id/findings" params={{ id }} className="crumb">
              Findings
            </Link>
          </Crumbs>
          <h1 title={f.title}>{headline(f.title)}</h1>
          <p className="sub">{findingState(f)}</p>
        </div>
        <span className={`pill${f.status === "open" ? " on" : ""}`}>{f.status.replace("-", " ")}</span>
      </div>

      <div className="with-rail">
        <div>
          <section className="section" style={{ marginTop: 0 }} aria-labelledby="fields-heading">
            <header>
              <h2 id="fields-heading">The seven fields</h2>
              <span className="note">what a report needs for every finding</span>
            </header>
            <Fields f={f} />
          </section>

          <section className="section" id="evidence" aria-labelledby="evidence-heading">
            <header>
              <h2 id="evidence-heading">Evidence</h2>
              <span className="note">{redactionLine(f.evidence)}</span>
            </header>
            {f.evidence.length === 0 ? (
              <div className="panel">
                <p className="empty">No evidence yet. It is captured when the finding is validated: the request and the response, with secrets removed.</p>
              </div>
            ) : (
              <div className="grid gap-3">
                {f.evidence.map((e) => (
                  <Piece key={e.id} e={e} />
                ))}
              </div>
            )}
          </section>

          <section className="section" aria-labelledby="sources-heading">
            <header>
              <h2 id="sources-heading">Sources</h2>
              <span className="note">{count(f.sources.length, "tool")} reported it</span>
            </header>
            <div className="panel">
              <Sources sources={f.sources} />
            </div>
          </section>

          <section className="section" aria-labelledby="standards-heading">
            <header>
              <h2 id="standards-heading">Standards</h2>
              <span className="note">from the CWE, once classified</span>
            </header>
            <div className="panel">
              <Standards f={f} />
            </div>
          </section>
        </div>

        <aside className="rail" aria-labelledby="risk-heading">
          <header className="rail-header">
            <h2 id="risk-heading">Risk and CVSS</h2>
            <span className="note">v3.1 base metrics</span>
          </header>
          <CvssCalculator f={f} store={(risk) => store.mutateAsync(risk)} />
        </aside>
      </div>
    </>
  );
}

/** A field that still holds the import's placeholder: a tool reported the finding and nobody has written this part yet. */
function Placeholder({ text }: { text: string }) {
  return (
    <>
      <span className="pill warn">Not written yet</span>
      <p className="muted mt-1">{text}</p>
    </>
  );
}

function Fields({ f }: { f: FindingDetail }) {
  const value: Record<FindingFieldKey, ReactNode> = {
    title: f.title,
    asset: (
      <>
        <span className="font-medium">{f.asset.name}</span>
        <span className="muted"> · {KIND_LABELS[f.asset.kind]}</span>
        <span className="block">{f.scope}</span>
      </>
    ),
    impact: f.impact === UNASSESSED_IMPACT ? <Placeholder text={f.impact} /> : <p className="prose">{f.impact}</p>,
    evidence: (
      <>
        {redactionLine(f.evidence)}
        {f.evidence.length ? (
          <>
            {" "}
            <a href="#evidence" className="crumb">
              See it below.
            </a>
          </>
        ) : null}
      </>
    ),
    risk: (
      <>
        <SeverityMark severity={f.risk.severity} />
        <span className="block muted">
          {f.risk.cvss ? (
            <>
              <span className="num text-[var(--text)]">{f.risk.cvss.baseScore.toFixed(1)}</span> · {f.risk.cvss.vector}
            </>
          ) : (
            "no CVSS vector: the severity is the worst a tool gave"
          )}
          {f.risk.likelihood || f.risk.impact ? ` · likelihood ${f.risk.likelihood ?? "unrated"}, impact ${f.risk.impact ?? "unrated"}` : null}
        </span>
      </>
    ),
    fix: f.fix === UNWRITTEN_FIX ? <Placeholder text={f.fix} /> : <p className="prose">{f.fix}</p>,
    retest: f.retest && f.retest.outcome !== "pending" ? (
      <>
        <span className="font-medium">{f.retest.outcome.replace("-", " ")}</span>
        {f.retest.testedAt ? <span className="muted"> · tested {isoDate(f.retest.testedAt)}</span> : null}
        {f.retest.notes ? <span className="block">{f.retest.notes}</span> : null}
      </>
    ) : (
      <span className="muted">No retest yet: it comes after the fix.</span>
    ),
  };
  return (
    <ol className="fields panel" aria-label="The seven fields">
      {FINDING_FIELDS.map((field) => (
        <li key={field.key}>
          <div className="name">
            <span role="term">{field.label}</span>
            <span className="q">{field.question}</span>
          </div>
          <div role="definition" className="value">
            {value[field.key]}
          </div>
        </li>
      ))}
    </ol>
  );
}

/** One piece of evidence: a request beside its response when it is a capture, the text whole otherwise, and the lines that carry a credential pointed at. */
function Piece({ e }: { e: Evidence }) {
  const secrets = secretLines(e.content);
  const parts = e.kind === "request-response" ? splitRequestResponse(e.content) : null;
  const meta = [EVIDENCE_KIND_LABELS[e.kind], e.source ? `from ${e.source.tool}` : null, e.capturedAt ? `captured ${relativeTime(e.capturedAt)}` : null].filter(Boolean).join(" · ");
  return (
    <article className="panel piece" aria-labelledby={`${e.id}-title`}>
      <header className="piece-head">
        <div>
          <h3 id={`${e.id}-title`}>{e.title ?? EVIDENCE_KIND_LABELS[e.kind]}</h3>
          <div className="muted text-[13px]">{meta}</div>
        </div>
        {e.redacted ? <span className="pill pos">Redacted</span> : <span className="pill warn">Not redacted</span>}
      </header>
      {secrets.length ? (
        <div className="notice mx-5 mb-3">
          {secrets.map((s) => (
            <div key={s.line}>
              Line {s.line} carries {s.why}: remove it before this goes in the report.
            </div>
          ))}
        </div>
      ) : null}
      {parts ? (
        <div className="capture">
          <div>
            <div className="cap">Request</div>
            <Code text={parts.request} secrets={secrets} offset={0} />
          </div>
          <div>
            <div className="cap">Response</div>
            <Code text={parts.response} secrets={secrets} offset={e.content.slice(0, e.content.indexOf(parts.response)).split(/\r?\n/).length - 1} />
          </div>
        </div>
      ) : (
        <div className="capture one">
          <Code text={e.content} secrets={secrets} offset={0} />
        </div>
      )}
    </article>
  );
}

/** The text as captured, one line per line, the flagged ones marked. `offset` is the line the text starts on in the whole capture. */
function Code({ text, secrets, offset }: { text: string; secrets: { line: number }[]; offset: number }) {
  const flagged = new Set(secrets.map((s) => s.line));
  return (
    <pre>
      {text.split(/\r?\n/).map((line, i) => (
        <span key={i} className={flagged.has(offset + i + 1) ? "secret" : undefined}>
          {line}
          {"\n"}
        </span>
      ))}
    </pre>
  );
}

/** The host of a reference, as the link's text: enough to know where it goes, short enough for a cell. */
function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

function Sources({ sources }: { sources: Source[] }) {
  if (sources.length === 0) return <p className="empty">No tool reported this: it was written by hand.</p>;
  return (
    <div className="table-wrap">
      <table className="fold" aria-label="Sources">
        <thead>
          <tr>
            <th>Tool</th>
            <th>Reported as</th>
            <th>Rated</th>
            <th className="n">Claimed</th>
            <th>Reference</th>
          </tr>
        </thead>
        <tbody>
          {sources.map((s) => (
            <tr key={`${s.tool}:${s.rawId}`}>
              <td className="id">{s.tool}</td>
              <td className="line2 break-all">{s.rawId}</td>
              <td className="line2">{s.severity ?? <span className="dash">—</span>}</td>
              <td className={`n line2${s.cvss ? "" : " quiet"}`} data-label="claimed">
                {s.cvss?.score !== undefined ? s.cvss.score.toFixed(1) : s.cvss?.vector ? "vector" : <span className="dash">—</span>}
              </td>
              <td className="key">
                {s.reference ? (
                  <a href={s.reference} target="_blank" rel="noopener noreferrer" className="crumb">
                    {hostOf(s.reference)}
                  </a>
                ) : (
                  <span className="dash">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Standards({ f }: { f: FindingDetail }) {
  const m = f.mappings;
  const rows: { label: string; value: string }[] = [
    { label: "CWE", value: m.cwe.map((n) => `CWE-${n}`).join(", ") },
    { label: "CVE", value: m.cve.join(", ") },
    { label: "OWASP Top 10", value: m.owaspTop10.map((id) => `${id} ${owaspTop10(id)?.name ?? ""}`.trim()).join(", ") },
    { label: "OWASP API Top 10", value: m.owaspApi.map((id) => `${id} ${owaspApiTop10(id)?.name ?? ""}`.trim()).join(", ") },
    { label: "ASVS", value: m.asvs.map((id) => `${id} ${asvsChapter(id)?.name ?? ""}`.trim()).join(", ") },
    { label: "CIS Controls", value: m.cis.map((n) => `Control ${n}`).join(", ") },
  ];
  return (
    <ul className="pairs" aria-label="Standards">
      {rows.map((r) => (
        <li key={r.label}>
          <span className="k">{r.label}</span>
          <span className="v">{r.value || <span className="dash">—</span>}</span>
        </li>
      ))}
    </ul>
  );
}

function Frame({ id, title, children }: { id: string; title: string; children: ReactNode }) {
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
            <Link to="/a/$id/findings" params={{ id }} className="crumb">
              Findings
            </Link>
          </Crumbs>
          <h1>{title}</h1>
        </div>
      </div>
      <div className="panel">
        <div className="failed">{children}</div>
      </div>
    </>
  );
}

export function FindingNotFound() {
  const { id } = findingRoute.useParams();
  return (
    <Frame id={id} title="Not found">
      <span>This finding is not here, or it is not yours.</span>
      <Link to="/a/$id/findings" params={{ id }} className="btn">
        Back to the findings
      </Link>
    </Frame>
  );
}

export function FindingFailed({ error }: ErrorComponentProps) {
  const router = useRouter();
  const { id } = findingRoute.useParams();
  return (
    <Frame id={id} title="Finding">
      <span>Couldn't load the finding: {messageOf(error)}.</span>
      <button type="button" className="btn" onClick={() => void router.invalidate()}>
        Retry
      </button>
    </Frame>
  );
}

