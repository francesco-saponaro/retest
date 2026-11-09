import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
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

describe("authentication", () => {
  it("answers /health without a token", async () => {
    const res = await t.app.inject({ method: "GET", url: "/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true });
  });

  it("refuses every other route without a token", async () => {
    const res = await t.app.inject({ method: "GET", url: "/assessments" });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: "missing token" });
  });

  it("refuses a bad token with 401 and says only that it is invalid", async () => {
    const res = await t.app.inject({ method: "GET", url: "/assessments", headers: { authorization: "Bearer not.a.token" } });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: "invalid token" });
  });

  it("refuses a basic auth header, not just a missing one", async () => {
    const res = await t.app.inject({ method: "GET", url: "/assessments", headers: { authorization: "Basic abc" } });
    expect(res.statusCode).toBe(401);
  });
});

describe("POST /assessments", () => {
  it("creates an assessment owned by the caller, in the scope phase, as a draft", async () => {
    const res = await t.as("francesco", {
      method: "POST",
      url: "/assessments",
      body: { name: "Juice Shop lab", client: "Me", scope: { targets: ["127.0.0.1"], authorizedBy: "me", authorizedAt: "2026-11-09T18:00:00Z" } },
    });
    expect(res.status).toBe(201);
    const a = res.json() as Record<string, unknown>;
    expect(a["id"]).toMatch(/^a-[0-9a-f]{12}$/);
    expect(a).toMatchObject({ name: "Juice Shop lab", client: "Me", phase: "scope", status: "draft", ownerId: "francesco" });
    expect((a["scope"] as Record<string, unknown>)["exclusions"]).toEqual([]);
    expect(a["createdAt"]).toMatch(/^\d{4}-\d{2}-\d{2}T.*Z$/);
  });

  it("refuses an assessment without a scope, naming the fields", async () => {
    const res = await t.as("francesco", { method: "POST", url: "/assessments", body: { name: "No scope" } });
    expect(res.status).toBe(400);
    const body = res.json() as { error: string; issues: { path: string; message: string }[] };
    expect(body.error).toBe("invalid body");
    expect(body.issues.map((i) => i.path)).toEqual(["scope"]);
  });

  it("refuses a scope with no targets or no one who authorised it", async () => {
    const res = await t.as("francesco", { method: "POST", url: "/assessments", body: { name: "Lab", scope: { targets: [] } } });
    expect(res.status).toBe(400);
    const body = res.json() as { issues: { path: string }[] };
    expect(body.issues.map((i) => i.path).sort()).toEqual(["scope.authorizedBy", "scope.targets"]);
  });

  it("refuses an owner or an id sent in the body, naming them", async () => {
    const res = await t.as("francesco", {
      method: "POST",
      url: "/assessments",
      body: { id: "a-chosen", ownerId: "someone-else", name: "Lab", scope: { targets: ["127.0.0.1"], authorizedBy: "me" } },
    });
    expect(res.status).toBe(400);
    expect((res.json() as { issues: { path: string }[] }).issues.map((i) => i.path).sort()).toEqual(["id", "ownerId"]);
  });

  it("refuses a body that is not JSON", async () => {
    const res = await t.as("francesco", { method: "POST", url: "/assessments", headers: { "content-type": "application/json" }, payload: "{not json" });
    expect(res.status).toBe(400);
  });
});

describe("GET /assessments", () => {
  it("lists only the caller's own assessments, newest first", async () => {
    await t.assessment("francesco", { name: "First" });
    await t.assessment("francesco", { name: "Second" });
    await t.assessment("someone-else", { name: "Theirs" });
    const res = await t.as("francesco", { method: "GET", url: "/assessments" });
    expect(res.status).toBe(200);
    const items = (res.json() as { items: { name: string }[] }).items;
    expect(items.map((a) => a.name)).toEqual(["Second", "First"]);
  });

  it("lists every assessment for an admin", async () => {
    await t.assessment("francesco");
    await t.assessment("someone-else");
    const res = await t.as("root", { role: "admin", method: "GET", url: "/assessments" });
    expect((res.json() as { items: unknown[] }).items).toHaveLength(2);
  });
});

describe("GET /assessments/:id", () => {
  it("returns the assessment with its totals", async () => {
    const id = await t.assessment("francesco");
    const res = await t.as("francesco", { method: "GET", url: `/assessments/${id}` });
    expect(res.status).toBe(200);
    expect(res.json()).toMatchObject({
      id,
      totals: {
        findings: 0,
        assets: 0,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        byPhase: { scope: 0, recon: 0, assessment: 0, validation: 0, risk: 0, remediation: 0 },
        byStatus: { open: 0, "false-positive": 0, "accepted-risk": 0, closed: 0 },
      },
    });
  });

  it("answers 404 for someone else's assessment, the same as for one that does not exist", async () => {
    const id = await t.assessment("francesco");
    const theirs = await t.as("someone-else", { method: "GET", url: `/assessments/${id}` });
    const missing = await t.as("someone-else", { method: "GET", url: "/assessments/a-000000000000" });
    expect(theirs.status).toBe(404);
    expect(missing.status).toBe(404);
    expect(theirs.json()).toEqual(missing.json());
  });

  it("lets an admin read it", async () => {
    const id = await t.assessment("francesco");
    const res = await t.as("root", { role: "admin", method: "GET", url: `/assessments/${id}` });
    expect(res.status).toBe(200);
  });
});

describe("PATCH /assessments/:id", () => {
  it("changes the name, the client and the scope, and bumps updatedAt", async () => {
    const id = await t.assessment("francesco");
    const before = (await t.as("francesco", { method: "GET", url: `/assessments/${id}` })).json() as { updatedAt: string };
    await new Promise((r) => setTimeout(r, 5));
    const res = await t.as("francesco", {
      method: "PATCH",
      url: `/assessments/${id}`,
      body: { name: "Renamed", scope: { targets: ["10.0.0.0/24"], exclusions: ["10.0.0.1"], authorizedBy: "the client" } },
    });
    expect(res.status).toBe(200);
    const a = res.json() as { name: string; scope: { exclusions: string[] }; updatedAt: string };
    expect(a.name).toBe("Renamed");
    expect(a.scope.exclusions).toEqual(["10.0.0.1"]);
    expect(a.updatedAt > before.updatedAt).toBe(true);
  });

  it("refuses to change the owner, the phase or the status here", async () => {
    const id = await t.assessment("francesco");
    const res = await t.as("francesco", { method: "PATCH", url: `/assessments/${id}`, body: { ownerId: "x", phase: "recon" } });
    expect(res.status).toBe(400);
    expect((res.json() as { issues: { path: string }[] }).issues.map((i) => i.path).sort()).toEqual(["ownerId", "phase"]);
  });

  it("is 404 for someone else's assessment", async () => {
    const id = await t.assessment("francesco");
    const res = await t.as("someone-else", { method: "PATCH", url: `/assessments/${id}`, body: { name: "Mine now" } });
    expect(res.status).toBe(404);
  });
});

describe("POST /assessments/:id/phase and /status", () => {
  it("moves the assessment to a phase and writes an audit line", async () => {
    const id = await t.assessment("francesco");
    const res = await t.as("francesco", { method: "POST", url: `/assessments/${id}/phase`, body: { phase: "recon" } });
    expect(res.status).toBe(200);
    expect((res.json() as { phase: string }).phase).toBe("recon");
    const audit = await t.as("francesco", { method: "GET", url: `/assessments/${id}/audit` });
    expect((audit.json() as { items: unknown[] }).items).toEqual([
      expect.objectContaining({ actor: "francesco", action: "phase", field: "phase", from: "scope", to: "recon", findingId: null }),
    ]);
  });

  it("refuses a phase that is not one of the six", async () => {
    const id = await t.assessment("francesco");
    const res = await t.as("francesco", { method: "POST", url: `/assessments/${id}/phase`, body: { phase: "exploitation" } });
    expect(res.status).toBe(400);
  });

  it("activates and closes an assessment, each with an audit line", async () => {
    const id = await t.assessment("francesco");
    expect((await t.as("francesco", { method: "POST", url: `/assessments/${id}/status`, body: { status: "active" } })).status).toBe(200);
    const closed = await t.as("francesco", { method: "POST", url: `/assessments/${id}/status`, body: { status: "closed" } });
    expect((closed.json() as { status: string }).status).toBe("closed");
    const audit = (await t.as("francesco", { method: "GET", url: `/assessments/${id}/audit` })).json() as { items: { to: string }[] };
    expect(audit.items.map((l) => l.to)).toEqual(["active", "closed"]);
  });

  it("does not write an audit line when nothing changes", async () => {
    const id = await t.assessment("francesco");
    await t.as("francesco", { method: "POST", url: `/assessments/${id}/phase`, body: { phase: "scope" } });
    const audit = (await t.as("francesco", { method: "GET", url: `/assessments/${id}/audit` })).json() as { items: unknown[] };
    expect(audit.items).toEqual([]);
  });
});

describe("DELETE /assessments/:id", () => {
  it("deletes the assessment and everything under it", async () => {
    const id = await t.assessment("francesco");
    const res = await t.as("francesco", { method: "DELETE", url: `/assessments/${id}` });
    expect(res.status).toBe(204);
    expect((await t.as("francesco", { method: "GET", url: `/assessments/${id}` })).status).toBe(404);
  });

  it("is 404 for someone else's", async () => {
    const id = await t.assessment("francesco");
    expect((await t.as("someone-else", { method: "DELETE", url: `/assessments/${id}` })).status).toBe(404);
    expect((await t.as("francesco", { method: "GET", url: `/assessments/${id}` })).status).toBe(200);
  });
});
