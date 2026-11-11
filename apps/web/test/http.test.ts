import { describe, expect, it, vi } from "vitest";
import { ApiError, httpClient } from "../src/api/http.js";

function fakeFetch(status: number, body: unknown) {
  return vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));
}

describe("httpClient", () => {
  it("lists assessments from GET /assessments with the bearer token", async () => {
    const fetch = fakeFetch(200, { items: [{ id: "a-1", name: "Juice Shop lab" }] });
    const client = httpClient({ baseUrl: "/api", token: () => "tok", fetch });
    const items = await client.listAssessments();
    expect(items).toEqual([{ id: "a-1", name: "Juice Shop lab" }]);
    const [url, init] = fetch.mock.calls[0]!;
    expect(String(url)).toBe("/api/assessments");
    expect(new Headers(init?.headers).get("authorization")).toBe("Bearer tok");
    expect(init?.method ?? "GET").toBe("GET");
  });

  it("reads one assessment with its totals, and its assets, imports and audit lines", async () => {
    const fetch = fakeFetch(200, { items: [] });
    const client = httpClient({ baseUrl: "http://127.0.0.1:3001", token: () => "tok", fetch });
    await client.getAssessment("a-1");
    await client.listAssets("a-1");
    await client.listImports("a-1");
    await client.listAudit("a-1");
    expect(fetch.mock.calls.map((c) => String(c[0]))).toEqual([
      "http://127.0.0.1:3001/assessments/a-1",
      "http://127.0.0.1:3001/assessments/a-1/assets",
      "http://127.0.0.1:3001/assessments/a-1/imports",
      "http://127.0.0.1:3001/assessments/a-1/audit",
    ]);
  });

  it("unwraps { items } lists and returns objects as they are", async () => {
    const fetch = vi.fn(async (url: string | URL | Request) => {
      const u = String(url);
      const body = u.endsWith("/assets") ? { items: [{ id: "asset-1" }] } : { id: "a-1", totals: { findings: 3 } };
      return new Response(JSON.stringify(body), { status: 200 });
    });
    const client = httpClient({ baseUrl: "/api", token: () => "tok", fetch });
    expect(await client.listAssets("a-1")).toEqual([{ id: "asset-1" }]);
    expect(await client.getAssessment("a-1")).toEqual({ id: "a-1", totals: { findings: 3 } });
  });

  it("sends no authorization header when there is no token", async () => {
    const fetch = fakeFetch(401, { error: "missing token" });
    const client = httpClient({ baseUrl: "/api", token: () => null, fetch });
    await expect(client.listAssessments()).rejects.toMatchObject({ status: 401, message: "missing token" });
    expect(new Headers(fetch.mock.calls[0]![1]?.headers).has("authorization")).toBe(false);
  });

  it("turns an error answer into an ApiError with the status and the API's message", async () => {
    const client = httpClient({ baseUrl: "/api", token: () => "tok", fetch: fakeFetch(404, { error: "assessment not found" }) });
    const err = await client.getAssessment("a-nope").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 404, message: "assessment not found" });
  });

  it("still fails sensibly when the answer is not JSON", async () => {
    const fetch = vi.fn(async () => new Response("<html>bad gateway</html>", { status: 502 }));
    const client = httpClient({ baseUrl: "/api", token: () => "tok", fetch });
    await expect(client.listAssessments()).rejects.toMatchObject({ status: 502, message: "request failed (502)" });
  });

  it("escapes the id in the path", async () => {
    const fetch = fakeFetch(200, {});
    const client = httpClient({ baseUrl: "/api", token: () => "tok", fetch });
    await client.getAssessment("a/../b");
    expect(String(fetch.mock.calls[0]![0])).toBe("/api/assessments/a%2F..%2Fb");
  });

  it("lists findings with the filters as query parameters, only the ones that are set", async () => {
    const fetch = fakeFetch(200, { items: [], total: 0, limit: 500, offset: 0 });
    const client = httpClient({ baseUrl: "/api", token: () => "tok", fetch });
    await client.listFindings("a-1", {});
    await client.listFindings("a-1", { severity: "critical", tool: "zap", phase: "assessment", owasp: "A01", assetId: "asset-web", q: "cors & co" });
    expect(fetch.mock.calls.map((c) => String(c[0]))).toEqual(["/api/assessments/a-1/findings?limit=500", "/api/assessments/a-1/findings?severity=critical&tool=zap&phase=assessment&owasp=A01&assetId=asset-web&q=cors+%26+co&limit=500"]);
    expect(await client.listFindings("a-1", {})).toEqual({ items: [], total: 0, limit: 500, offset: 0 });
  });

  it("reads one finding by its id", async () => {
    const fetch = fakeFetch(200, { id: "f-1", asset: { id: "asset-1" } });
    const client = httpClient({ baseUrl: "/api", token: () => "tok", fetch });
    expect(await client.getFinding("f-1")).toEqual({ id: "f-1", asset: { id: "asset-1" } });
    expect(String(fetch.mock.calls[0]![0])).toBe("/api/findings/f-1");
  });

  it("patches a finding as JSON", async () => {
    const fetch = fakeFetch(200, { id: "f-1", risk: { severity: "high" } });
    const client = httpClient({ baseUrl: "/api", token: () => "tok", fetch });
    const risk = { severity: "high" as const, cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", baseScore: 7.5 } };
    expect(await client.updateFinding("f-1", { risk })).toEqual({ id: "f-1", risk: { severity: "high" } });
    const [url, init] = fetch.mock.calls[0]!;
    expect(String(url)).toBe("/api/findings/f-1");
    expect(init?.method).toBe("PATCH");
    expect(new Headers(init?.headers).get("content-type")).toBe("application/json");
    expect(new Headers(init?.headers).get("authorization")).toBe("Bearer tok");
    expect(JSON.parse(String(init?.body))).toEqual({ risk });
  });

  it("gives the API's validation message when a patch is refused", async () => {
    const client = httpClient({ baseUrl: "/api", token: () => "tok", fetch: fakeFetch(400, { error: "invalid body", issues: [{ path: "risk.severity", message: "severity does not match the CVSS score" }] }) });
    await expect(client.updateFinding("f-1", { risk: { severity: "low" } })).rejects.toMatchObject({ status: 400, message: "invalid body: risk.severity severity does not match the CVSS score" });
  });
});
