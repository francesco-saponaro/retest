import { useQuery, useSuspenseQuery, type UseQueryResult } from "@tanstack/react-query";
import { Link, useRouter, type ErrorComponentProps } from "@tanstack/react-router";
import type { Asset, AssetKind } from "@retest/schema";
import type { ReactNode } from "react";
import type { AssessmentDetail, AuditLine, ImportOut, Totals } from "../api/client.js";
import { PhaseBoard } from "../components/PhaseBoard.js";
import { SeverityTray } from "../components/SeverityTray.js";
import { StatusPill } from "../components/StatusPill.js";
import { auditSentence, count, findingLine, isoDate, messageOf, phaseLine, relativeTime, scopeLine } from "../lib/format.js";
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
  const findings = useQuery({ ...findingsQuery(client, id, {}), enabled: (history.data?.some((l) => l.findingId) ?? false) });
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
        <div className="flex items-center gap-3">
          <span className="muted whitespace-nowrap">{a.client ?? ""}</span>
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
        <SeverityTray totals={a.totals} />
        <div className="mt-3">
          <StatusStrip totals={a.totals} />
        </div>
      </section>

      <div className="two section">
        <section>
          <header className="flex items-baseline justify-between gap-4 mb-3">
            <h2 className="text-[18px] leading-6 font-medium">Scope</h2>
            <span className="note">{scopeLine(a.scope)}{windowLine(a.scope)}</span>
          </header>
          <Scope a={a} assets={assets.data} />
        </section>
        <section>
          <header className="flex items-baseline justify-between gap-4 mb-3">
            <h2 className="text-[18px] leading-6 font-medium">Assets</h2>
            <span className="note">{assets.data ? count(assets.data.length, "asset") : ""}</span>
          </header>
          <Block query={assets} what="the assets" rows={4}>
            {(items) => <AssetsTable items={items} />}
          </Block>
        </section>
      </div>

      <section className="section">
        <header>
          <h2>Imports</h2>
          <span className="note">{imports.data ? `${count(imports.data.length, "scanner file")}, newest first` : ""}</span>
        </header>
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
function Scope({ a, assets }: { a: Pick<AssessmentDetail, "client" | "scope">; assets: Asset[] | undefined }) {
  const covers = (t: string) => assets?.filter((x) => coveredByScope(x, { ...a.scope, targets: [t], exclusions: [] })).length;
  const rows = [...a.scope.targets.map((t) => ({ t, excluded: false })), ...a.scope.exclusions.map((t) => ({ t, excluded: true }))];
  return (
    <div className="panel">
      <div className="table-wrap">
        <table className="fold" aria-label="Scope">
          <thead>
            <tr>
              <th>Target</th>
              <th className="n">Covers</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.excluded ? "x" : "t"}-${r.t}`}>
                <td className="id">{r.t}</td>
                <td className="n key">{r.excluded ? <span className="pill warn">Excluded</span> : coverText(covers(r.t))}</td>
              </tr>
            ))}
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

function AssetsTable({ items }: { items: Asset[] }) {
  if (items.length === 0) return <p className="empty">No assets yet: the first import creates them.</p>;
  return (
    <div className="table-wrap">
      <table className="fold" aria-label="Assets">
        <thead>
          <tr>
            <th>Asset</th>
            <th>Kind</th>
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
                  {i.warnings.map((w) => (
                    <span key={w} className="warning">
                      {w}
                    </span>
                  ))}
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
