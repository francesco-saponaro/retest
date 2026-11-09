import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { assets } from "../src/db/index.js";
import { testApp, type TestApp } from "./app.js";

let t: TestApp;

beforeAll(async () => {
  t = await testApp();
});

afterAll(async () => {
  await t.close();
});

beforeEach(async () => {
  await t.reset();
});

describe("POST /assessments/:id/assets", () => {
  it("adds an asset to the assessment, in scope by default", async () => {
    const id = await t.assessment("francesco");
    const res = await t.as("francesco", { method: "POST", url: `/assessments/${id}/assets`, body: { kind: "web-app", name: "Juice Shop", url: "http://127.0.0.1:3000", host: "127.0.0.1", port: 3000 } });
    expect(res.status).toBe(201);
    const a = res.json() as Record<string, unknown>;
    expect(a["id"]).toMatch(/^asset-[0-9a-f]{12}$/);
    expect(a).toMatchObject({ assessmentId: id, kind: "web-app", name: "Juice Shop", url: "http://127.0.0.1:3000", inScope: true, tags: [] });
  });

  it("enforces the schema: a web app needs a url, a port is a port", async () => {
    const id = await t.assessment("francesco");
    const noUrl = await t.as("francesco", { method: "POST", url: `/assessments/${id}/assets`, body: { kind: "web-app", name: "Juice Shop" } });
    expect(noUrl.status).toBe(400);
    expect((noUrl.json() as { issues: { path: string }[] }).issues.map((i) => i.path)).toEqual(["url"]);
    const badPort = await t.as("francesco", { method: "POST", url: `/assessments/${id}/assets`, body: { kind: "service", name: "ssh", host: "10.0.10.11", port: 70000 } });
    expect(badPort.status).toBe(400);
  });

  it("refuses an assessmentId in the body that is not the one in the path", async () => {
    const id = await t.assessment("francesco");
    const other = await t.assessment("francesco");
    const res = await t.as("francesco", { method: "POST", url: `/assessments/${id}/assets`, body: { assessmentId: other, kind: "host", name: "10.0.0.1", host: "10.0.0.1" } });
    expect(res.status).toBe(400);
  });

  it("is 404 on someone else's assessment", async () => {
    const id = await t.assessment("francesco");
    const res = await t.as("someone-else", { method: "POST", url: `/assessments/${id}/assets`, body: { kind: "host", name: "10.0.0.1", host: "10.0.0.1" } });
    expect(res.status).toBe(404);
  });
});

describe("GET /assessments/:id/assets and GET /assessments/:id/assets/:assetId", () => {
  it("lists the assets of the assessment by name", async () => {
    const id = await t.assessment("francesco");
    for (const name of ["zeta", "alpha"]) await t.as("francesco", { method: "POST", url: `/assessments/${id}/assets`, body: { kind: "host", name, host: name } });
    const res = await t.as("francesco", { method: "GET", url: `/assessments/${id}/assets` });
    expect((res.json() as { items: { name: string }[] }).items.map((a) => a.name)).toEqual(["alpha", "zeta"]);
  });

  it("lets two assessments hold an asset with the same id, each its own row", async () => {
    const a = await t.assessment("francesco");
    const b = await t.assessment("someone-else");
    await t.db.insert(assets).values([
      { id: "asset-host-127-0-0-1", assessmentId: a, kind: "host", name: "localhost", host: "127.0.0.1", port: null, url: null, inScope: true, tags: [] },
      { id: "asset-host-127-0-0-1", assessmentId: b, kind: "host", name: "the same host, elsewhere", host: "127.0.0.1", port: null, url: null, inScope: false, tags: [] },
    ]);
    const mine = (await t.as("francesco", { method: "GET", url: `/assessments/${a}/assets/asset-host-127-0-0-1` })).json() as { name: string };
    const theirs = (await t.as("someone-else", { method: "GET", url: `/assessments/${b}/assets/asset-host-127-0-0-1` })).json() as { name: string };
    expect([mine.name, theirs.name]).toEqual(["localhost", "the same host, elsewhere"]);
  });

  it("returns one asset with its finding count, through the assessment's owner check", async () => {
    const id = await t.assessment("francesco");
    const created = (await t.as("francesco", { method: "POST", url: `/assessments/${id}/assets`, body: { kind: "host", name: "box", host: "10.0.0.1" } })).json() as { id: string };
    const mine = await t.as("francesco", { method: "GET", url: `/assessments/${id}/assets/${created.id}` });
    expect(mine.status).toBe(200);
    expect(mine.json()).toMatchObject({ id: created.id, name: "box", findingCount: 0 });
    const theirs = await t.as("someone-else", { method: "GET", url: `/assessments/${id}/assets/${created.id}` });
    expect(theirs.status).toBe(404);
    const wrongAssessment = await t.as("francesco", { method: "GET", url: `/assessments/${await t.assessment("francesco")}/assets/${created.id}` });
    expect(wrongAssessment.status).toBe(404);
  });
});

describe("PATCH /assessments/:id/assets/:assetId", () => {
  it("renames, tags and takes an asset out of scope", async () => {
    const id = await t.assessment("francesco");
    const created = (await t.as("francesco", { method: "POST", url: `/assessments/${id}/assets`, body: { kind: "host", name: "box", host: "10.0.0.1" } })).json() as { id: string };
    const res = await t.as("francesco", { method: "PATCH", url: `/assessments/${id}/assets/${created.id}`, body: { name: "the printer", inScope: false, tags: ["excluded"] } });
    expect(res.status).toBe(200);
    expect(res.json()).toMatchObject({ name: "the printer", inScope: false, tags: ["excluded"], host: "10.0.0.1" });
  });

  it("keeps the schema's rules when patching: a web app cannot lose its url", async () => {
    const id = await t.assessment("francesco");
    const created = (await t.as("francesco", { method: "POST", url: `/assessments/${id}/assets`, body: { kind: "web-app", name: "shop", url: "http://127.0.0.1:3000" } })).json() as { id: string };
    const res = await t.as("francesco", { method: "PATCH", url: `/assessments/${id}/assets/${created.id}`, body: { url: null } });
    expect(res.status).toBe(400);
  });

  it("cannot move an asset to another assessment", async () => {
    const id = await t.assessment("francesco");
    const created = (await t.as("francesco", { method: "POST", url: `/assessments/${id}/assets`, body: { kind: "host", name: "box", host: "10.0.0.1" } })).json() as { id: string };
    const res = await t.as("francesco", { method: "PATCH", url: `/assessments/${id}/assets/${created.id}`, body: { assessmentId: "a-other" } });
    expect(res.status).toBe(400);
  });
});
