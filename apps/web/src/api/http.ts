import { ApiError, PAGE, type ApiClient, type FindingFilter } from "./client.js";

export { ApiError };

export interface HttpClientOptions {
  /** Where the API is: `/api` behind the dev server's proxy, or the API's own origin. */
  baseUrl: string;
  /** The bearer token for every request, or null when the person has not connected yet. */
  token: () => string | null;
  fetch?: typeof fetch;
}

interface Refusal {
  error?: unknown;
  issues?: { path?: unknown; message?: unknown }[];
}

/** The API's one-line reason, with the fields it named when it refused a body. */
function messageOf(body: unknown, status: number): string {
  const r = body && typeof body === "object" ? (body as Refusal) : {};
  if (typeof r.error !== "string") return `request failed (${status})`;
  const issues = Array.isArray(r.issues) ? r.issues.filter((i) => typeof i.message === "string").map((i) => `${typeof i.path === "string" && i.path ? `${i.path} ` : ""}${String(i.message)}`) : [];
  return issues.length ? `${r.error}: ${issues.join("; ")}` : r.error;
}

/** The API over HTTP. Every answer is JSON; every refusal becomes an `ApiError`. */
export function httpClient(options: HttpClientOptions): ApiClient {
  const doFetch = options.fetch ?? ((input, init) => fetch(input, init));
  const base = options.baseUrl.replace(/\/$/, "");

  async function call<T>(method: "GET" | "POST" | "PATCH", path: string, payload?: unknown): Promise<T> {
    const headers = new Headers({ accept: "application/json" });
    const token = options.token();
    if (token) headers.set("authorization", `Bearer ${token}`);
    const init: RequestInit = { method, headers };
    if (payload !== undefined) {
      headers.set("content-type", "application/json");
      init.body = JSON.stringify(payload);
    }
    const res = await doFetch(`${base}${path}`, init);
    const body = (await res.json().catch(() => undefined)) as unknown;
    if (!res.ok) throw new ApiError(res.status, messageOf(body, res.status));
    return body as T;
  }

  const get = <T>(path: string) => call<T>("GET", path);
  const items = async <T>(path: string): Promise<T[]> => (await get<{ items: T[] }>(path)).items;
  const id = (s: string) => encodeURIComponent(s);

  /** `?severity=critical&tool=zap&limit=500`: only the filters that are set, in the contract's order. */
  const query = (f: FindingFilter): string => {
    const p = new URLSearchParams();
    for (const key of ["severity", "tool", "phase", "owasp", "assetId", "q"] as const) {
      const v = f[key];
      if (v) p.set(key, v);
    }
    p.set("limit", String(PAGE));
    return `?${p.toString()}`;
  };

  return {
    mode: "api",
    listAssessments: () => items("/assessments"),
    getAssessment: (aid) => get(`/assessments/${id(aid)}`),
    listAssets: (aid) => items(`/assessments/${id(aid)}/assets`),
    listImports: (aid) => items(`/assessments/${id(aid)}/imports`),
    listAudit: (aid) => items(`/assessments/${id(aid)}/audit`),
    listFindings: (aid, filter) => get(`/assessments/${id(aid)}/findings${query(filter)}`),
    getFinding: (fid) => get(`/findings/${id(fid)}`),
    updateFinding: (fid, patch) => call("PATCH", `/findings/${id(fid)}`, patch),
    setFindingPhase: (fid, change) => call("POST", `/findings/${id(fid)}/phase`, change),
    setFindingStatus: (fid, change) => call("POST", `/findings/${id(fid)}/status`, change),
    recordRetest: (fid, input) => call("POST", `/findings/${id(fid)}/retest`, input),
    addEvidence: (fid, input) => call("POST", `/findings/${id(fid)}/evidence`, input),
    updateEvidence: (eid, patch) => call("PATCH", `/evidence/${id(eid)}`, patch),
    listFindingAudit: (fid) => items(`/findings/${id(fid)}/audit`),
  };
}
