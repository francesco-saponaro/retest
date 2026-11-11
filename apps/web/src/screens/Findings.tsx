import { useQuery, useSuspenseQuery } from "@tanstack/react-query";
import { Link, useNavigate, useRouter, type ErrorComponentProps } from "@tanstack/react-router";
import { useWindowVirtualizer } from "@tanstack/react-virtual";
import { OWASP_TOP_10_2021, PHASES, PHASE_DETAILS, SEVERITY_LABELS, TOOLS, type Asset } from "@retest/schema";
import { useRef, useState, type FormEvent } from "react";
import type { FindingFilter, FindingSummary } from "../api/client.js";
import { Crumbs } from "../components/Crumbs.js";
import { SeverityMark } from "../components/SeverityMark.js";
import { REPORT_ORDER, findingsLine, messageOf, shortPhase } from "../lib/format.js";
import { assessmentQuery, assetsQuery, findingsQuery } from "../queries.js";
import { findingsRoute } from "../router.js";

const ROW = 65;

/**
 * Every finding of one assessment, most severe first. The question: which one do I open next? The
 * line under the title counts what the filters left and says whether any of it has been validated;
 * the rows are drawn only where the window is, so five hundred of them cost what twenty do.
 */
export function Findings() {
  const { client } = findingsRoute.useRouteContext();
  const { id } = findingsRoute.useParams();
  const filter = findingsRoute.useSearch();
  const { data: a } = useSuspenseQuery(assessmentQuery(client, id));
  const assets = useQuery(assetsQuery(client, id));
  const page = useQuery(findingsQuery(client, id, filter));
  const filtered = Object.keys(filter).length > 0;

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
          <h1>Findings</h1>
          <p className="sub">{page.data ? findingsLine({ all: a.totals.findings, matched: page.data.total, items: page.data.items, filtered }) : page.isError ? "" : "Loading the findings."}</p>
        </div>
      </div>

      <FilterBar filter={filter} assets={assets.data ?? []} />

      {page.isPending ? (
        <div className="panel" aria-busy="true">
          {Array.from({ length: 6 }, (_, i) => (
            <div key={i} className="flex items-center gap-3 px-5" style={{ height: ROW }}>
              <span className="skeleton h-4 w-80" />
              <span className="skeleton h-4 w-20" />
              <span className="skeleton h-4 w-16" />
            </div>
          ))}
        </div>
      ) : page.isError ? (
        <div className="panel">
          <div className="failed">
            <span>Couldn't load the findings: {messageOf(page.error)}.</span>
            <button type="button" className="btn" onClick={() => void page.refetch()}>
              Retry
            </button>
          </div>
        </div>
      ) : page.data.items.length === 0 ? (
        <div className="panel">
          <p className="empty">{filtered ? "No findings match these filters." : "No findings yet: the first import creates them."}</p>
        </div>
      ) : (
        <div className="panel">
          <Table id={id} items={page.data.items} assets={assets.data ?? []} />
        </div>
      )}
    </>
  );
}

/** The five filters and the search. A select applies at once; the search applies on Enter. All of it is the URL. */
function FilterBar({ filter, assets }: { filter: FindingFilter; assets: Asset[] }) {
  const navigate = useNavigate({ from: findingsRoute.fullPath });
  const [q, setQ] = useState(filter.q ?? "");
  const set = (patch: Partial<Record<keyof FindingFilter, string>>) =>
    void navigate({
      search: (prev) => {
        const next: Record<string, string> = { ...(prev as Record<string, string>) };
        for (const [k, v] of Object.entries(patch)) {
          if (v) next[k] = v;
          else delete next[k];
        }
        return next as FindingFilter;
      },
    });
  const search = (e: FormEvent) => {
    e.preventDefault();
    set({ q: q.trim() });
  };
  const clear = () => {
    setQ("");
    void navigate({ search: {} });
  };
  const filtered = Object.keys(filter).length > 0;

  return (
    <form className="toolbar" role="search" onSubmit={search}>
      <input type="search" className="input search" aria-label="Search" placeholder="Title or scope" value={q} onChange={(e) => setQ(e.target.value)} />
      <select className="select" aria-label="Severity" value={filter.severity ?? ""} onChange={(e) => set({ severity: e.target.value })}>
        <option value="">Any severity</option>
        {REPORT_ORDER.map((s) => (
          <option key={s} value={s}>
            {SEVERITY_LABELS[s]}
          </option>
        ))}
      </select>
      <select className="select" aria-label="Tool" value={filter.tool ?? ""} onChange={(e) => set({ tool: e.target.value })}>
        <option value="">Any tool</option>
        {TOOLS.map((t) => (
          <option key={t} value={t}>
            {t}
          </option>
        ))}
      </select>
      <select className="select" aria-label="Phase" value={filter.phase ?? ""} onChange={(e) => set({ phase: e.target.value })}>
        <option value="">Any phase</option>
        {PHASES.map((p) => (
          <option key={p} value={p}>
            {PHASE_DETAILS[p].label}
          </option>
        ))}
      </select>
      <select className="select" aria-label="OWASP Top 10" value={filter.owasp ?? ""} onChange={(e) => set({ owasp: e.target.value })}>
        <option value="">Any category</option>
        {OWASP_TOP_10_2021.map((c) => (
          <option key={c.id} value={c.id}>
            {c.id} {c.name}
          </option>
        ))}
      </select>
      <select className="select" aria-label="Asset" value={filter.assetId ?? ""} onChange={(e) => set({ assetId: e.target.value })}>
        <option value="">Any asset</option>
        {assets.map((x) => (
          <option key={x.id} value={x.id}>
            {x.name}
          </option>
        ))}
      </select>
      {filtered ? (
        <button type="button" className="btn text" onClick={clear}>
          Clear
        </button>
      ) : null}
    </form>
  );
}

/**
 * The rows, virtualised against the window: a spacer row above and below the ones in view keeps
 * the scrollbar honest, and the header stays under the bar while the page scrolls.
 */
function Table({ id, items, assets }: { id: string; items: FindingSummary[]; assets: Asset[] }) {
  const names = new Map(assets.map((x) => [x.id, x.name]));
  const ref = useRef<HTMLTableSectionElement>(null);
  const virtualizer = useWindowVirtualizer({
    count: items.length,
    estimateSize: () => ROW,
    // Two screens of rows each way: a table the size of the lab never unmounts a row; a long one still draws only what is near.
    overscan: 30,
    scrollMargin: ref.current ? ref.current.getBoundingClientRect().top + window.scrollY : 0,
    // In a test browser every box is 0px tall; a row that measured nothing keeps its estimate.
    measureElement: (el) => el.getBoundingClientRect().height || ROW,
  });
  const rows = virtualizer.getVirtualItems();
  const first = rows[0];
  const last = rows[rows.length - 1];
  const above = first ? first.start - virtualizer.options.scrollMargin : 0;
  const below = last ? virtualizer.getTotalSize() - (last.end - virtualizer.options.scrollMargin) : 0;

  return (
    <div className="table-wrap open">
      <table className="fold findings" aria-label="Findings">
        <thead>
          <tr>
            <th>Finding</th>
            <th>Asset</th>
            <th>Severity</th>
            <th className="n">CVSS</th>
            <th>Phase</th>
            <th>Tools</th>
            <th className="n">Evidence</th>
            <th>OWASP</th>
          </tr>
        </thead>
        <tbody ref={ref}>
          {above > 0 ? (
            <tr aria-hidden="true" className="spacer">
              <td colSpan={8} style={{ height: above }} />
            </tr>
          ) : null}
          {rows.map((row) => {
            const f = items[row.index]!;
            return (
              <tr key={f.id} data-index={row.index} ref={virtualizer.measureElement}>
                <td className="id">
                  <Link to="/a/$id/findings/$fid" params={{ id, fid: f.id }}>
                    {f.title}
                  </Link>
                  <span className="sub">{f.scope}</span>
                </td>
                <td className="line2">{names.get(f.assetId) ?? f.assetId}</td>
                <td className="key">
                  <SeverityMark severity={f.risk.severity} />
                </td>
                <td className={`n${f.risk.cvss ? "" : " quiet"}`} data-label="CVSS">
                  {f.risk.cvss ? f.risk.cvss.baseScore.toFixed(1) : <span className="dash">—</span>}
                </td>
                <td className="line2">{shortPhase(f.phase)}</td>
                <td className="line2">{[...new Set(f.sources.map((s) => s.tool))].join(", ")}</td>
                <td className="n" data-label="evidence">
                  {f.evidenceCount}
                </td>
                <td className={`line2${f.mappings.owaspTop10.length ? "" : " quiet"}`}>{f.mappings.owaspTop10.length ? f.mappings.owaspTop10.join(", ") : <span className="dash">—</span>}</td>
              </tr>
            );
          })}
          {below > 0 ? (
            <tr aria-hidden="true" className="spacer">
              <td colSpan={8} style={{ height: below }} />
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}

export function FindingsFailed({ error }: ErrorComponentProps) {
  const router = useRouter();
  const { id } = findingsRoute.useParams();
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
          <h1>Findings</h1>
        </div>
      </div>
      <div className="panel">
        <div className="failed">
          <span>Couldn't load the findings: {messageOf(error)}.</span>
          <button type="button" className="btn" onClick={() => void router.invalidate()}>
            Retry
          </button>
        </div>
      </div>
    </>
  );
}
