import { ApiError, type ApiClient } from "./client.js";

export { ApiError };

export interface HttpClientOptions {
  /** Where the API is: `/api` behind the dev server's proxy, or the API's own origin. */
  baseUrl: string;
  /** The bearer token for every request, or null when the person has not connected yet. */
  token: () => string | null;
  fetch?: typeof fetch;
}

/** The API over HTTP. Every answer is JSON; every refusal becomes an `ApiError`. */
export function httpClient(options: HttpClientOptions): ApiClient {
  const doFetch = options.fetch ?? ((input, init) => fetch(input, init));
  const base = options.baseUrl.replace(/\/$/, "");

  async function get<T>(path: string): Promise<T> {
    const headers = new Headers({ accept: "application/json" });
    const token = options.token();
    if (token) headers.set("authorization", `Bearer ${token}`);
    const res = await doFetch(`${base}${path}`, { method: "GET", headers });
    const body = (await res.json().catch(() => undefined)) as unknown;
    if (!res.ok) {
      const message = body && typeof body === "object" && typeof (body as { error?: unknown }).error === "string" ? (body as { error: string }).error : `request failed (${res.status})`;
      throw new ApiError(res.status, message);
    }
    return body as T;
  }

  const items = async <T>(path: string): Promise<T[]> => (await get<{ items: T[] }>(path)).items;
  const id = (s: string) => encodeURIComponent(s);

  return {
    mode: "api",
    listAssessments: () => items("/assessments"),
    getAssessment: (aid) => get(`/assessments/${id(aid)}`),
    listAssets: (aid) => items(`/assessments/${id(aid)}/assets`),
    listImports: (aid) => items(`/assessments/${id(aid)}/imports`),
    listAudit: (aid) => items(`/assessments/${id(aid)}/audit`),
  };
}
