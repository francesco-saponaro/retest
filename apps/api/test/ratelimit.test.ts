import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { testApp, type TestApp } from "./app.js";
import { fixture } from "./helpers.js";

let t: TestApp;

beforeAll(async () => {
  t = await testApp({ rateLimit: { max: 5, timeWindow: "1 minute" }, importRateLimit: { max: 2, timeWindow: "1 minute" } });
});

afterAll(async () => {
  await t.close();
});

describe("rate limiting", () => {
  it("answers 429 after the limit, per user, with the headers that say so", async () => {
    const aid = await t.assessment("francesco");
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) statuses.push((await t.as("francesco", { method: "GET", url: `/assessments/${aid}` })).status);
    expect(statuses).toEqual([200, 200, 200, 200, 429, 429]);
    const res = await t.app.inject({ method: "GET", url: `/assessments/${aid}`, headers: { authorization: `Bearer ${await t.token("francesco")}` } });
    expect(res.statusCode).toBe(429);
    expect(res.headers["x-ratelimit-limit"]).toBe("5");
    expect(res.headers["retry-after"]).toBeDefined();
    expect(res.json()).toMatchObject({ error: expect.stringMatching(/Rate limit exceeded/) });
    // Another user is counted on their own.
    expect((await t.as("someone-else", { method: "GET", url: "/assessments" })).status).toBe(200);
  });

  it("counts unauthenticated requests by address, before any token is read", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) statuses.push((await t.app.inject({ method: "GET", url: "/assessments", remoteAddress: "203.0.113.9" })).statusCode);
    expect(statuses).toEqual([401, 401, 401, 401, 401, 429]);
  });

  it("gives imports their own, tighter limit", async () => {
    const aid = await t.assessment("someone-else");
    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) {
      statuses.push((await t.as("someone-else", { method: "POST", url: "/imports", body: { assessmentId: aid, tool: "nmap", content: fixture("nmap/juice-shop.xml") } })).status);
    }
    expect(statuses).toEqual([201, 201, 429]);
  });
});
