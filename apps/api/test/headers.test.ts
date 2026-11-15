import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { testApp, type TestApp } from "./app.js";

let t: TestApp;
let aid: string;

beforeAll(async () => {
  t = await testApp();
  aid = await t.assessment("francesco");
});
afterAll(async () => {
  await t.close();
});

const EXPECTED = {
  "x-content-type-options": "nosniff",
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
};

describe("response headers", () => {
  it("are on every answer: public, refused, JSON, markdown and not found", async () => {
    const answers = [
      await t.app.inject({ method: "GET", url: "/health" }),
      await t.app.inject({ method: "GET", url: "/assessments" }),
      await t.app.inject({ method: "GET", url: "/nowhere" }),
    ];
    for (const res of answers) expect(res.headers).toMatchObject(EXPECTED);
    expect((await t.as("francesco", { method: "GET", url: "/assessments" })).headers).toMatchObject(EXPECTED);
    expect((await t.as("francesco", { method: "GET", url: `/assessments/${aid}/summary.md` })).headers).toMatchObject(EXPECTED);
  });

  it("never let another site read an answer: no CORS header, even when asked", async () => {
    const res = await t.as("francesco", { method: "GET", url: "/assessments", headers: { origin: "https://evil.example" } });
    expect(res.status).toBe(200);
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    const preflight = await t.app.inject({ method: "OPTIONS", url: "/assessments", headers: { origin: "https://evil.example", "access-control-request-method": "GET" } });
    expect(preflight.headers["access-control-allow-origin"]).toBeUndefined();
    expect(preflight.headers["access-control-allow-headers"]).toBeUndefined();
  });

  it("say nothing about the server", async () => {
    const res = await t.app.inject({ method: "GET", url: "/health" });
    expect(res.headers["x-powered-by"]).toBeUndefined();
    expect(res.headers.server).toBeUndefined();
  });
});
