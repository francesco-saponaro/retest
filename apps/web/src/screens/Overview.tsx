import { useQuery, useSuspenseQuery, type UseQueryResult } from "@tanstack/react-query";
import { Link, useRouter, type ErrorComponentProps } from "@tanstack/react-router";
import { OWASP_TOP_10_2021, type Asset, type AssetKind } from "@retest/schema";
import type { ReactNode } from "react";
import type { AssessmentDetail, AuditLine, FindingSummary, ImportOut, Totals } from "../api/client.js";
import { Explain } from "../components/Explain.js";
import { PhaseBoard } from "../components/PhaseBoard.js";
import { SeverityTray } from "../components/SeverityTray.js";
import { StatusPill } from "../components/StatusPill.js";
import { SeverityMark } from "../components/SeverityMark.js";
import { auditSentence, count, findingLine, headline, isoDate, messageOf, phaseLine, relativeTime, scopeLine } from "../lib/format.js";
import { coveredByScope } from "@retest/api/services/scope.js";
import { assessmentQuery, assetsQuery, auditQuery, findingsQuery, importsQuery } from "../queries.js";
import { assessmentRoute } from "../router.js";

/**
 * One assessment at a glance. The question: where does it stand, and how much of it is still only
 * what a scanner said? The board answers the first, the line under the title the second.
 */
export function Overview() {
  const { client } = assessmentRoute.useRouteContext();
  const { id } = assessmentRoute.useParams();
  const { data: a } = useSuspenseQuery(assessmentQuery(client, id));
  const assets = useQuery(assetsQuery(client, id));
  const imports = useQuery(importsQuery(client, id));
  const history = useQuery(auditQuery(client, id));
  const findings = useQuery(findingsQuery(client, id, {}));
  const toolsByAsset = assetTools(findings.data?.items);
  const titles = new Map((findings.data?.items ?? []).map((f) => [f.id, f.title]));

  return (
    <>
      <div className="title-row">
        <div>
          <Link to="/" className="crumb">
            Assessments
          </Link>
          <h1>{a.name}</h1>
          <p className="sub">{findingLine(a.totals)}</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <span className="muted">{a.client ?? ""}</span>
          <StatusPill status={a.status} />
          {a.totals.findings > 0 ? (
            <Link to="/a/$id/report" params={{ id }} className="btn">
              Report
            </Link>
          ) : null}
        </div>
      </div>

      <section className="section" style={{ marginTop: 0 }}>
        <header>
          <h2>Where it stands</h2>
          <span className="note">{phaseLine(a.phase)}</span>
        </header>
        <Explain>
          Every assessment moves through six steps, from left to right. The highlighted box is the step the whole assessment is in; the number in each box is how many findings are in that step right now.
        </Explain>
        <PhaseBoard current={a.phase} totals={a.totals} />
      </section>

      <section className="section">
        <header>
          <h2>Findings</h2>
          {a.totals.findings > 0 ? (
            <Link to="/a/$id/findings" params={{ id }} className="crumb">
              All {count(a.totals.findings, "finding")}
            </Link>
          ) : (
            <span className="note">nothing on {count(a.totals.assets, "asset")}</span>
          )}
        </header>
        <Explain
          terms={[
            ["Critical, high", "Could let someone take over the system or reach its data. Check these first."],
            ["Medium, low", "A weakness that helps an attacker, or needs other conditions to be dangerous."],
            ["Informational", "Not a flaw on its own: a fact worth knowing, like the software version a server shows."],
            ["Open", "Still to be dealt with. Every finding starts here."],
            ["False positive", "A person checked and the scanner was wrong. Kept, with the reason, so nobody checks it twice."],
            ["Accepted risk", "Real, but the owner decided to live with it, in writing, with a reason."],
            ["Closed", "Fixed, and a retest proved the fix works."],
          ]}
          label="What the severities and statuses mean"
        >
          A finding is one possible problem on one thing, for example "an old OpenSSL with a known flaw, inside the Juice Shop image". When two scanners report the same problem, Retest keeps one finding with both as sources. The severity is how bad the problem would be if it is real; until a person checks it, it is only what the scanner said.
        </Explain>
        <SeverityTray totals={a.totals} />
        <div className="mt-3">
          <StatusStrip totals={a.totals} />
        </div>
      </section>

      {findings.data && findings.data.items.length > 0 ? (
        <section className="section" aria-labelledby="by-tool-heading">
          <header>
            <h2 id="by-tool-heading">What each scanner found</h2>
            <span className="note">most serious first</span>
          </header>
          <Explain>
            Each scanner looks at a different side of the target, so each one finds different kinds of problems. Here are the three most serious from each, with the kind of risk each one is under it (from the OWASP Top 10, the standard list of web security risks); open one to see the details, or see everything that tool reported. A finding two tools agreed on is counted under both.
          </Explain>
          <ByTool id={id} items={findings.data.items} />
        </section>
      ) : null}

      <div className="two section">
        <section>
          <header className="flex items-baseline justify-between gap-4 mb-3">
            <h2 className="text-[18px] leading-6 font-medium">Scope</h2>
            <span className="note">{scopeLine(a.scope)}{windowLine(a.scope)}</span>
          </header>
          <Explain>
            The scope is the written permission: what you are allowed to test. Scanning anything outside it can be illegal, so it comes first. A <strong>target</strong> is one line of that permission: a machine's address, a website's URL, a container image or a code repository.
          </Explain>
          <Scope a={a} assets={assets.data} tools={toolsByAsset} />
        </section>
        <section>
          <header className="flex items-baseline justify-between gap-4 mb-3">
            <h2 className="text-[18px] leading-6 font-medium">Assets</h2>
            <span className="note">{assets.data ? count(assets.data.length, "asset") : ""}</span>
          </header>
          <Explain>
            An asset is a real thing a scanner found inside a target: the machine, the website on it, the image, the code. Each one is checked against the scope; anything outside it is marked <strong>Out of scope</strong> so it cannot slip into the work.
          </Explain>
          <Block query={assets} what="the assets" rows={4}>
            {(items) => <AssetsTable items={items} tools={toolsByAsset} />}
          </Block>
        </section>
      </div>

      <section className="section">
        <header>
          <h2>Imports</h2>
          <span className="note">{imports.data ? `${count(imports.data.length, "scanner file")}, newest first` : ""}</span>
        </header>
        <Explain
          terms={[
            ["Parsed", "How many results Retest read from the file."],
            ["Created", "How many became new findings."],
            ["Merged", "How many described a problem already on the list (from this tool or another), so they were added to that finding as one more source instead of being counted twice."],
            ["Assets", "How many new assets the file added. 0 means everything it reported was on assets already known."],
            ["Warnings", "Anything Retest could not take at face value. \"No CVSS v3 vector\" means the tool gave a severity word but not the formula behind it, so the rating cannot be checked."],
          ]}
        >
          Each row is one file a scanner wrote, imported as it was, without edits. Every tool writes its own format; Retest reads all of them into the same kind of finding. Importing the same file twice changes nothing.
        </Explain>
        <Block query={imports} what="the imports" rows={3}>
          {(items) => <ImportsTable items={items} />}
        </Block>
      </section>

      <section className="section" aria-labelledby="history-heading">
        <header>
          <h2 id="history-heading">History</h2>
          {history.data && history.data.length > RECENT ? (
            <Link to="/a/$id/audit" params={{ id }} className="crumb">
              All {count(history.data.length, "entry")}
            </Link>
          ) : (
            <span className="note">{history.data ? (history.data.length ? "everything so far, newest first" : "") : ""}</span>
          )}
        </header>
        <Explain>
          Every change is written down with who made it, when and why: imports, phase changes, a finding marked as a false positive. Nothing is edited quietly, so the trail can be shown to a client or an auditor.
        </Explain>
        <Block query={history} what="the history" rows={3}>
          {(lines) => <RecentHistory id={id} lines={lines} titles={titles} />}
        </Block>
      </section>
    </>
  );
}

const RECENT = 5;

/** The last few things that happened, newest first, each finding named by its title once the list has loaded. */
function RecentHistory({ id, lines, titles }: { id: string; lines: AuditLine[]; titles: Map<string, string> }) {
  if (lines.length === 0) return <p className="empty">Nothing has happened yet: the first import will be the first entry.</p>;
  return (
    <ol className="history" aria-label="Recent history">
      {[...lines].reverse().slice(0, RECENT).map((l) => (
        <li key={l.id}>
          <span className="when muted">{relativeTime(l.at)}</span>
          <span className="what">
            <span className="font-medium">{l.actor}</span>{" "}
            {l.findingId ? (
              <>
                <Link to="/a/$id/findings/$fid" params={{ id, fid: l.findingId }} className="crumb">
                  {titles.get(l.findingId) ?? l.findingId}
                </Link>
                : {auditSentence(l)}
              </>
            ) : (
              auditSentence(l)
            )}
            {l.reason ? <span className="block muted">{l.reason}</span> : null}
          </span>
        </li>
      ))}
    </ol>
  );
}

const STATUS_LABELS: Record<keyof Totals["byStatus"], string> = {
  open: "Open",
  "false-positive": "False positive",
  "accepted-risk": "Accepted risk",
  closed: "Closed",
};

function StatusStrip({ totals }: { totals: Totals }) {
  return (
    <ul className="statuses panel" aria-label="Findings by status">
      {(Object.keys(STATUS_LABELS) as (keyof Totals["byStatus"])[]).map((s) => {
        const n = totals.byStatus[s];
        return (
          <li key={s} className="kpi">
            <div className="label">{STATUS_LABELS[s]}</div>
            <div className={`value num${n === 0 ? " zero" : ""}`}>{n}</div>
          </li>
        );
      })}
    </ul>
  );
}

/** " · 2026-11-01 to 2026-11-30" when the authorisation has a window. */
function windowLine(s: Pick<AssessmentDetail["scope"], "startsAt" | "endsAt">): string {
  if (!s.startsAt && !s.endsAt) return "";
  return ` · ${s.startsAt ? isoDate(s.startsAt) : "open"} to ${s.endsAt ? isoDate(s.endsAt) : "open"}`;
}

function coverText(n: number | undefined) {
  if (n === undefined) return <span className="dash">—</span>;
  if (n === 0) return <span className="muted">nothing yet</span>;
  return count(n, "asset");
}

/**
 * What was authorised, one target per row, with how many of the assets each target covers on its
 * own (the same rule the import applies). A target covering nothing has not been scanned yet.
 */
function Scope({ a, assets, tools }: { a: Pick<AssessmentDetail, "client" | "scope">; assets: Asset[] | undefined; tools: Map<string, string[]> }) {
  const covered = (t: string) => assets?.filter((x) => coveredByScope(x, { ...a.scope, targets: [t], exclusions: [] }));
  const covers = (t: string) => covered(t)?.length;
  const testedBy = (t: string) => [...new Set((covered(t) ?? []).flatMap((x) => tools.get(x.id) ?? []))].sort();
  const rows = [...a.scope.targets.map((t) => ({ t, excluded: false })), ...a.scope.exclusions.map((t) => ({ t, excluded: true }))];
  return (
    <div className="panel">
      <div className="table-wrap">
        <table className="fold" aria-label="Scope">
          <thead>
            <tr>
              <th>Target</th>
              <th>Tested by</th>
              <th className="n">Covers</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.excluded ? "x" : "t"}-${r.t}`}>
                <td className="id">{r.t}</td>
                <td className="line2">{r.excluded ? <span className="dash">—</span> : toolList(testedBy(r.t))}</td>
                <td className="n key">{r.excluded ? <span className="pill warn">Excluded</span> : coverText(covers(r.t))}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const TOOL_NAMES: Record<string, string> = { nmap: "Nmap", nuclei: "Nuclei", zap: "ZAP", semgrep: "Semgrep", trivy: "Trivy", prowler: "Prowler", manual: "By hand" };

/** Which tools reported findings on each asset, from the findings' sources. */
function assetTools(items: FindingSummary[] | undefined): Map<string, string[]> {
  const out = new Map<string, Set<string>>();
  for (const f of items ?? []) {
    const set = out.get(f.assetId) ?? new Set<string>();
    for (const s of f.sources) set.add(s.tool);
    out.set(f.assetId, set);
  }
  return new Map([...out].map(([k, v]) => [k, [...v].sort()]));
}

function toolList(tools: string[]) {
  if (tools.length === 0) return <span className="muted">nothing yet</span>;
  return tools.map((t) => TOOL_NAMES[t] ?? t).join(", ");
}

/** "A03 Injection" in plain words: the OWASP Top 10 names, without the codes. */
function categoryNames(ids: string[]): string {
  return ids.map((x) => OWASP_TOP_10_2021.find((c) => c.id === x)?.name ?? x).join(", ");
}

const TOOL_ORDER = ["nmap", "nuclei", "zap", "semgrep", "trivy", "prowler", "manual"];

const TOOL_LOOKS_AT: Record<string, string> = {
  nmap: "the machine: which ports are open and what answers on them",
  nuclei: "the website, with ready-made checks for known mistakes",
  zap: "the website, by browsing it like a visitor and reading every answer",
  semgrep: "the source code, for dangerous patterns",
  trivy: "the container image, for libraries with known flaws",
  prowler: "the cloud account's settings",
  manual: "what a person added by hand",
};

/** Per tool: how many findings it reported, its three most serious (the list comes most serious first), and a link to all of them. */
function ByTool({ id, items }: { id: string; items: FindingSummary[] }) {
  const tools = TOOL_ORDER.filter((t) => items.some((f) => f.sources.some((s) => s.tool === t)));
  return (
    <div className="panel">
      <div className="table-wrap">
        <table className="fold" aria-label="What each scanner found">
          <thead>
            <tr>
              <th>Scanner</th>
              <th>Its most serious findings</th>
              <th className="n">Findings</th>
            </tr>
          </thead>
          <tbody>
            {tools.map((t) => {
              const mine = items.filter((f) => f.sources.some((s) => s.tool === t));
              return (
                <tr key={t}>
                  <td className="id">
                    {TOOL_NAMES[t] ?? t}
                    <span className="sub">looks at {TOOL_LOOKS_AT[t] ?? "its own target"}</span>
                  </td>
                  <td className="line2">
                    <ul className="by-tool">
                      {mine.slice(0, 3).map((f) => (
                        <li key={f.id}>
                          <SeverityMark severity={f.risk.severity} />
                          <span>
                            <Link to="/a/$id/findings/$fid" params={{ id, fid: f.id }}>
                              {headline(f.title, 90)}
                            </Link>
                            {f.mappings.owaspTop10.length ? <span className="block muted">{categoryNames(f.mappings.owaspTop10)}</span> : null}
                          </span>
                        </li>
                      ))}
                    </ul>
                    {mine.length > 3 ? (
                      <Link to="/a/$id/findings" params={{ id }} search={{ tool: t as never }} className="crumb">
                        All {count(mine.length, "finding")} from {TOOL_NAMES[t] ?? t}
                      </Link>
                    ) : null}
                  </td>
                  <td className="n key">{mine.length}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const KIND_LABELS: Record<AssetKind, string> = {
  host: "Host",
  service: "Service",
  "web-app": "Web app",
  api: "API",
  repository: "Repository",
  "container-image": "Container image",
  "cloud-account": "Cloud account",
  "cloud-resource": "Cloud resource",
};

/** The address under the name, when the name does not already say it. */
function assetSub(x: Asset): string | null {
  const where = x.url ?? (x.host ? (x.port ? `${x.host}:${x.port}` : x.host) : null);
  return where && where !== x.name && !x.name.includes(where) ? where : null;
}

function AssetsTable({ items, tools }: { items: Asset[]; tools: Map<string, string[]> }) {
  if (items.length === 0) return <p className="empty">No assets yet: the first import creates them.</p>;
  return (
    <div className="table-wrap">
      <table className="fold" aria-label="Assets">
        <thead>
          <tr>
            <th>Asset</th>
            <th>Kind</th>
            <th>Found by</th>
            <th>Coverage</th>
          </tr>
        </thead>
        <tbody>
          {items.map((x) => (
            <tr key={x.id}>
              <td className="id">
                {x.name}
                {assetSub(x) ? <span className="muted font-normal"> · {assetSub(x)}</span> : null}
              </td>
              <td className="line2">{KIND_LABELS[x.kind]}</td>
              <td className="line2">{toolList(tools.get(x.id) ?? [])}</td>
              <td className="key">{x.inScope ? <span className="muted">In scope</span> : <span className="pill warn">Out of scope</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ImportsTable({ items }: { items: ImportOut[] }) {
  if (items.length === 0) return <p className="empty">Nothing imported yet.</p>;
  return (
    <div className="table-wrap">
      <table className="fold" aria-label="Imports">
        <thead>
          <tr>
            <th>Tool</th>
            <th>File</th>
            <th className="n">Parsed</th>
            <th className="n">Created</th>
            <th className="n">Merged</th>
            <th className="n">Assets</th>
            <th>Warnings</th>
            <th className="n">When</th>
          </tr>
        </thead>
        <tbody>
          {items.map((i) => (
            <tr key={i.id}>
              <td className="id">{i.tool}</td>
              <td className="line2 muted">{i.filename ?? <span className="dash">—</span>}</td>
              <td className="n" data-label="parsed">{i.parsed}</td>
              <td className="n" data-label="created">{i.created}</td>
              <td className="n" data-label="merged">{i.merged}</td>
              <td className="n" data-label="assets">{i.assetsCreated}</td>
              {i.warnings.length ? (
                <td className="line2">
                  <Warnings items={i.warnings} />
                </td>
              ) : (
                <td className="line2 quiet">
                  <span className="dash">—</span>
                </td>
              )}
              <td className="n line2 muted">{relativeTime(i.at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** A file's warnings: all of them when there are a few, the first two and a fold for the rest when there are many. */
function Warnings({ items }: { items: string[] }) {
  const shown = items.length > 3 ? items.slice(0, 2) : items;
  return (
    <>
      {shown.map((w, n) => (
        <span key={`${n}-${w}`} className="warning">
          {w}
        </span>
      ))}
      {items.length > 3 ? (
        <details className="more-warnings">
          <summary>Show all {items.length} warnings</summary>
          {items.slice(2).map((w, n) => (
            <span key={`${n}-${w}`} className="warning">
              {w}
            </span>
          ))}
        </details>
      ) : null}
    </>
  );
}

/** A block of the screen that loads on its own: rows of grey while it loads, the failure inside it with a retry, then its content. */
function Block<T>({ query, what, rows, children }: { query: UseQueryResult<T>; what: string; rows: number; children: (data: T) => ReactNode }) {
  if (query.isPending) {
    return (
      <div className="panel" aria-busy="true">
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} className="flex items-center gap-3 px-5" style={{ height: "var(--row-height)" }}>
            <span className="skeleton h-4 w-40" />
            <span className="skeleton h-4 w-24" />
          </div>
        ))}
      </div>
    );
  }
  if (query.isError) {
    return (
      <div className="panel">
        <div className="failed">
          <span>Couldn't load {what}: {query.error.message}.</span>
          <button type="button" className="btn" onClick={() => void query.refetch()}>
            Retry
          </button>
        </div>
      </div>
    );
  }
  return <div className="panel">{children(query.data)}</div>;
}

export function OverviewNotFound() {
  return (
    <>
      <div className="title-row">
        <div>
          <Link to="/" className="crumb">
            Assessments
          </Link>
          <h1>Not found</h1>
          <p className="sub">This assessment is not here, or it is not yours.</p>
        </div>
      </div>
      <div className="panel">
        <div className="failed">
          <span>The API answers the same way for an assessment that does not exist and for one that belongs to someone else.</span>
          <Link to="/" className="btn">
            Back to the assessments
          </Link>
        </div>
      </div>
    </>
  );
}

export function OverviewFailed({ error }: ErrorComponentProps) {
  const router = useRouter();
  return (
    <>
      <div className="title-row">
        <div>
          <Link to="/" className="crumb">
            Assessments
          </Link>
          <h1>Assessment</h1>
        </div>
      </div>
      <div className="panel">
        <div className="failed">
          <span>Couldn't load the assessment: {messageOf(error)}.</span>
          <button type="button" className="btn" onClick={() => void router.invalidate()}>
            Retry
          </button>
        </div>
      </div>
    </>
  );
}
