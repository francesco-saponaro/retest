import { useMutation, useQuery, useQueryClient, useSuspenseQuery } from "@tanstack/react-query";
import { Link, useRouter, type ErrorComponentProps } from "@tanstack/react-router";
import { EVIDENCE_KINDS, FINDING_FIELDS, UNASSESSED_IMPACT, UNWRITTEN_FIX, asvsChapter, isWritten, owaspApiTop10, owaspTop10, type Evidence, type EvidenceKind, type FindingFieldKey, type Source } from "@retest/schema";
import { useId, useState, type FormEvent, type ReactNode } from "react";
import type { AuditLine, EvidencePatch, FindingDetail, FindingPatch, NewEvidence } from "../api/client.js";
import { Crumbs } from "../components/Crumbs.js";
import { CvssCalculator } from "../components/CvssCalculator.js";
import { SeverityMark } from "../components/SeverityMark.js";
import { Workflow } from "../components/Workflow.js";
import { EVIDENCE_KIND_LABELS, redactionLine, secretLines, splitRequestResponse } from "../lib/evidence.js";
import { auditSentence, count, findingState, headline, isoDate, messageOf, phaseLine, relativeTime } from "../lib/format.js";
import { assessmentQuery, findingAuditQuery, findingQuery } from "../queries.js";
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
  const history = useQuery(findingAuditQuery(client, fid));
  const queryClient = useQueryClient();
  // Every change goes through the client and comes back by reading the finding again: the screen never guesses the result.
  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["findings", fid] });
    await queryClient.invalidateQueries({ queryKey: ["assessments", id] });
  };
  const patch = useMutation({ mutationFn: (p: FindingPatch) => client.updateFinding(fid, p), onSuccess: refresh });
  const addEvidence = useMutation({ mutationFn: (e: NewEvidence) => client.addEvidence(fid, e), onSuccess: refresh });
  const patchEvidence = useMutation({ mutationFn: ({ eid, p }: { eid: string; p: EvidencePatch }) => client.updateEvidence(eid, p), onSuccess: refresh });
  const act = {
    phase: (c: Parameters<typeof client.setFindingPhase>[1]) => client.setFindingPhase(fid, c).then(refresh),
    status: (c: Parameters<typeof client.setFindingStatus>[1]) => client.setFindingStatus(fid, c).then(refresh),
    retest: (i: Parameters<typeof client.recordRetest>[1]) => client.recordRetest(fid, i).then(refresh),
  };

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
        <span className={`pill${f.status === "open" ? " on" : ""}${f.status === "closed" ? " off" : ""}`}>{f.status.replace("-", " ")}</span>
      </div>

      <section className="section" style={{ marginTop: 0 }} aria-labelledby="workflow-heading">
        <header>
          <h2 id="workflow-heading">Where it stands</h2>
          <span className="note">{phaseLine(f.phase)}</span>
        </header>
        <Workflow f={f} act={act} />
      </section>

      <div className="with-rail section">
        <div>
          <section className="section" style={{ marginTop: 0 }} aria-labelledby="fields-heading">
            <header>
              <h2 id="fields-heading">The seven fields</h2>
              <span className="note">what a report needs for every finding</span>
            </header>
            <Fields f={f} write={(p) => patch.mutateAsync(p)} />
          </section>

          <section className="section" id="evidence" aria-labelledby="evidence-heading">
            <header>
              <h2 id="evidence-heading">Evidence</h2>
              <span className="note">{redactionLine(f.evidence)}</span>
            </header>
            <EvidenceList f={f} add={(e) => addEvidence.mutateAsync(e)} patch={(eid, p) => patchEvidence.mutateAsync({ eid, p })} />
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

          <section className="section" aria-labelledby="history-heading">
            <header>
              <h2 id="history-heading">History</h2>
              <span className="note">{history.data ? (history.data.length ? `${count(history.data.length, "entry")}, newest first` : "") : ""}</span>
            </header>
            <div className="panel">
              <History lines={history.data} failed={history.isError ? messageOf(history.error) : null} retry={() => void history.refetch()} />
            </div>
          </section>
        </div>

        <aside className="rail" aria-labelledby="risk-heading">
          <header className="rail-header">
            <h2 id="risk-heading">Risk and CVSS</h2>
            <span className="note">v3.1 base metrics</span>
          </header>
          <CvssCalculator f={f} store={(risk) => patch.mutateAsync({ risk })} />
        </aside>
      </div>
    </>
  );
}

/** What happened to this finding, newest first: each line is who, when, what, and the reason given. */
function History({ lines, failed, retry }: { lines: AuditLine[] | undefined; failed: string | null; retry: () => void }) {
  if (failed) {
    return (
      <div className="failed">
        <span>Couldn't load the history: {failed}.</span>
        <button type="button" className="btn" onClick={retry}>
          Retry
        </button>
      </div>
    );
  }
  if (!lines) {
    return (
      <div aria-busy="true" className="px-5">
        <div className="flex items-center gap-3" style={{ height: "var(--row-height)" }}>
          <span className="skeleton h-4 w-40" />
          <span className="skeleton h-4 w-24" />
        </div>
      </div>
    );
  }
  if (lines.length === 0) return <p className="empty">Nothing has happened to this finding yet: it is as the import left it.</p>;
  return (
    <ol className="history" aria-label="History of this finding">
      {[...lines].reverse().map((l) => (
        <li key={l.id}>
          <span className="when muted">{relativeTime(l.at)}</span>
          <span className="what">
            <span className="font-medium">{l.actor}</span> {auditSentence(l)}
            {l.reason ? <span className="block muted">{l.reason}</span> : null}
          </span>
        </li>
      ))}
    </ol>
  );
}

/** One of the written fields, edited in place: a textarea where the text was, Save and Cancel, the API's refusal in words. */
function Writable({ field, text, placeholder, write }: { field: "impact" | "fix"; text: string; placeholder: string; write: (p: FindingPatch) => Promise<unknown> }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const id = useId();
  const written = isWritten(text);
  const label = field === "impact" ? "Impact" : "Fix";
  const verb = written ? "Edit" : "Write";

  const start = () => {
    setDraft(written ? text : "");
    setProblem(null);
    setEditing(true);
  };
  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!draft.trim()) return setProblem("write something, or cancel");
    setBusy(true);
    setProblem(null);
    try {
      await write({ [field]: draft.trim() });
      setEditing(false);
    } catch (err) {
      setProblem(messageOf(err));
    } finally {
      setBusy(false);
    }
  };

  if (editing) {
    return (
      <form className="field" onSubmit={(e) => void save(e)} aria-label={`${verb} the ${field}`}>
        <label htmlFor={id} className="sr-only">
          {label}
        </label>
        <textarea id={id} className="input area" rows={5} value={draft} onChange={(e) => setDraft(e.target.value)} placeholder={placeholder} autoFocus />
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy}>
            Save the {field}
          </button>
          <button type="button" className="btn text" onClick={() => setEditing(false)}>
            Cancel
          </button>
          {problem ? <span style={{ color: "var(--negative)" }}>Not saved: {problem}.</span> : null}
        </div>
      </form>
    );
  }
  return (
    <>
      {written ? <p className="prose">{text}</p> : <Placeholder text={text} />}
      <button type="button" className="btn text write" onClick={start}>
        {verb} the {field}
      </button>
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

function Fields({ f, write }: { f: FindingDetail; write: (p: FindingPatch) => Promise<unknown> }) {
  const editable = f.status !== "closed";
  const value: Record<FindingFieldKey, ReactNode> = {
    title: f.title,
    asset: (
      <>
        <span className="font-medium">{f.asset.name}</span>
        <span className="muted"> · {KIND_LABELS[f.asset.kind]}</span>
        <span className="block">{f.scope}</span>
      </>
    ),
    impact: editable ? (
      <Writable field="impact" text={f.impact} placeholder="What can happen, and under which conditions: the asset, the mechanism, the consequence now, and what would make it worse." write={write} />
    ) : f.impact === UNASSESSED_IMPACT ? (
      <Placeholder text={f.impact} />
    ) : (
      <p className="prose">{f.impact}</p>
    ),
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
    fix: editable ? (
      <Writable field="fix" text={f.fix} placeholder="The concrete change, and how to check it was made." write={write} />
    ) : f.fix === UNWRITTEN_FIX ? (
      <Placeholder text={f.fix} />
    ) : (
      <p className="prose">{f.fix}</p>
    ),
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

/** The evidence, with the form that adds a piece a person captured and, on each piece, the controls that redact it. */
function EvidenceList({ f, add, patch }: { f: FindingDetail; add: (e: NewEvidence) => Promise<unknown>; patch: (eid: string, p: EvidencePatch) => Promise<unknown> }) {
  const [adding, setAdding] = useState(false);
  const editable = f.status !== "closed";
  return (
    <>
      {editable ? (
        <div className="mb-3 flex items-center gap-3">
          <button type="button" className="btn add-evidence" aria-expanded={adding} onClick={() => setAdding(!adding)}>
            Add evidence
          </button>
          <span className="muted">A request and its response, a command and its output, or a note: what proves the claim, with secrets removed.</span>
        </div>
      ) : null}
      {adding ? (
        <AddEvidence
          add={async (e) => {
            await add(e);
            setAdding(false);
          }}
          cancel={() => setAdding(false)}
        />
      ) : null}
      {f.evidence.length === 0 ? (
        <div className="panel">
          <p className="empty">No evidence yet. It is captured when the finding is validated: the request and the response, with secrets removed.</p>
        </div>
      ) : (
        <div className="grid gap-3">
          {f.evidence.map((e) => (
            <Piece key={e.id} e={e} patch={editable ? (p) => patch(e.id, p) : null} />
          ))}
        </div>
      )}
    </>
  );
}

function AddEvidence({ add, cancel }: { add: (e: NewEvidence) => Promise<unknown>; cancel: () => void }) {
  const [kind, setKind] = useState<EvidenceKind>("request-response");
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [redacted, setRedacted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const id = useId();
  const flagged = secretLines(content);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return setProblem("paste what was captured");
    setBusy(true);
    setProblem(null);
    try {
      await add({ kind, content, redacted, ...(title.trim() ? { title: title.trim() } : {}) });
    } catch (err) {
      setProblem(messageOf(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="panel move-form mb-3" onSubmit={(e) => void submit(e)} aria-label="Add evidence">
      <div className="two-fields">
        <div className="field">
          <label htmlFor={`${id}-kind`}>Kind</label>
          <select id={`${id}-kind`} className="select" value={kind} onChange={(e) => setKind(e.target.value as EvidenceKind)}>
            {EVIDENCE_KINDS.map((k) => (
              <option key={k} value={k}>
                {EVIDENCE_KIND_LABELS[k]}
              </option>
            ))}
          </select>
        </div>
        <div className="field grow">
          <label htmlFor={`${id}-title`}>Title</label>
          <input id={`${id}-title`} className="input" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="GET /rest/user/whoami with a foreign Origin" />
        </div>
      </div>
      <div className="field">
        <label htmlFor={`${id}-content`}>Content</label>
        <textarea id={`${id}-content`} className="input area mono" rows={8} value={content} onChange={(e) => setContent(e.target.value)} placeholder={kind === "request-response" ? "The request, a blank line, the response" : "As captured"} spellCheck={false} />
        {flagged.length ? (
          <div className="notice">
            {flagged.map((s) => (
              <div key={s.line}>
                Line {s.line} carries {s.why}: remove it before this goes in the report.
              </div>
            ))}
          </div>
        ) : (
          <div className="hint">Lines that carry a Cookie, an Authorization header, a token or a key are pointed out here.</div>
        )}
      </div>
      <label className="check">
        <input type="checkbox" checked={redacted} disabled={flagged.length > 0} onChange={(e) => setRedacted(e.target.checked)} />
        Captured with secrets removed: it may go in the report
      </label>
      <div className="actions">
        <button type="submit" className="btn primary" disabled={busy}>
          Save the evidence
        </button>
        <button type="button" className="btn text" onClick={cancel}>
          Cancel
        </button>
        {problem ? <span style={{ color: "var(--negative)" }}>Not saved: {problem}.</span> : null}
      </div>
    </form>
  );
}

/**
 * One piece of evidence: a request beside its response when it is a capture, the text whole
 * otherwise, and the lines that carry a credential pointed at. It can be edited in place, and it is
 * marked redacted only once no line is flagged: the viewer points, a person removes, and only then
 * does the report get it.
 */
function Piece({ e, patch }: { e: Evidence; patch: ((p: EvidencePatch) => Promise<unknown>) | null }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const id = useId();
  const secrets = secretLines(e.content);
  const parts = e.kind === "request-response" ? splitRequestResponse(e.content) : null;
  const meta = [EVIDENCE_KIND_LABELS[e.kind], e.source ? `from ${e.source.tool}` : null, e.capturedAt ? `captured ${relativeTime(e.capturedAt)}` : null].filter(Boolean).join(" · ");

  const run = async (p: EvidencePatch) => {
    if (!patch) return;
    setBusy(true);
    setProblem(null);
    try {
      await patch(p);
      setEditing(false);
    } catch (err) {
      setProblem(messageOf(err));
    } finally {
      setBusy(false);
    }
  };

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
      {editing ? (
        <form
          className="field px-5 pb-5"
          onSubmit={(ev) => {
            ev.preventDefault();
            if (!draft.trim()) return setProblem("the text cannot be empty");
            void run({ content: draft });
          }}
          aria-label="Edit the evidence"
        >
          <label htmlFor={id} className="sr-only">
            Evidence text
          </label>
          <textarea id={id} className="input area mono" rows={Math.min(16, Math.max(6, draft.split("\n").length + 1))} value={draft} onChange={(ev) => setDraft(ev.target.value)} spellCheck={false} autoFocus />
          <div className="actions">
            <button type="submit" className="btn primary" disabled={busy}>
              Save the text
            </button>
            <button type="button" className="btn text" onClick={() => setEditing(false)}>
              Cancel
            </button>
            {problem ? <span style={{ color: "var(--negative)" }}>Not saved: {problem}.</span> : null}
          </div>
        </form>
      ) : parts ? (
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
      {patch && !editing ? (
        <footer className="piece-foot">
          {e.redacted ? (
            <button type="button" className="btn text" disabled={busy} onClick={() => void run({ redacted: false })}>
              Mark as not redacted
            </button>
          ) : (
            <button type="button" className="btn" disabled={busy || secrets.length > 0} onClick={() => void run({ redacted: true })}>
              Mark as redacted
            </button>
          )}
          <button
            type="button"
            className="btn text"
            onClick={() => {
              setDraft(e.content);
              setProblem(null);
              setEditing(true);
            }}
          >
            Edit the text
          </button>
          {secrets.length && !e.redacted ? <span className="muted">Remove the flagged {secrets.length === 1 ? "line" : "lines"} first: only a person who has taken the secret out can say it is redacted.</span> : null}
          {problem ? <span style={{ color: "var(--negative)" }}>Not done: {problem}.</span> : null}
        </footer>
      ) : null}
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

