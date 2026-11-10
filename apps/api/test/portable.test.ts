import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { newId } from "../src/http.js";
import { LAB_RUNS, seedLab } from "../src/lab.js";
import { testApp } from "./app.js";

/**
 * The services, the row mappers and the lab seed also run in the browser, where the demo build
 * drives them against PostgreSQL compiled to WebAssembly. Nothing in that set may reach for a
 * Node built-in; the files that need one (the server, the CLI seed, the migrator) stay outside it.
 */
const src = fileURLToPath(new URL("../src/", import.meta.url));

const packages = fileURLToPath(new URL("../../../packages/", import.meta.url));

const portable = [
  "http.ts",
  "rows.ts",
  "lab.ts",
  "db/index.ts",
  "db/schema.ts",
  ...readdirSync(`${src}services`).map((f) => `services/${f}`),
  ...readdirSync(`${packages}parsers/src`).map((f) => `../../../packages/parsers/src/${f}`),
  ...readdirSync(`${packages}schema/src`, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => `../../../packages/schema/src/${e.parentPath.slice(`${packages}schema/src`.length).replace(/^\//, "")}${e.parentPath.length > `${packages}schema/src`.length ? "/" : ""}${e.name}`),
];

describe("the browser-portable set", () => {
  it.each(portable)("%s imports no Node built-in", (file) => {
    const text = readFileSync(`${src}${file}`, "utf8");
    expect(text).not.toMatch(/from\s+["']node:/);
    expect(text).not.toMatch(/import\(\s*["']node:/);
  });
});

describe("newId", () => {
  it("is the prefix, a dash and twelve hex digits", () => {
    expect(newId("a")).toMatch(/^a-[0-9a-f]{12}$/);
    expect(newId("imp")).toMatch(/^imp-[0-9a-f]{12}$/);
  });

  it("does not repeat", () => {
    const ids = new Set(Array.from({ length: 200 }, () => newId("f")));
    expect(ids.size).toBe(200);
  });
});

describe("seedLab with a reader of its own", () => {
  it("imports the six fixtures through whatever reads them", async () => {
    const t = await testApp();
    try {
      const fixtures = fileURLToPath(new URL("../../../packages/parsers/fixtures/", import.meta.url));
      const asked: string[] = [];
      const result = await seedLab(t.db, {
        ownerId: "francesco",
        read: (file) => {
          asked.push(file);
          return readFileSync(`${fixtures}${file}`, "utf8");
        },
      });
      expect(asked).toEqual(LAB_RUNS.map((r) => r.file));
      expect(result.imports.map((i) => i.created)).toEqual([4, 11, 3, 7, 5, 7]);
    } finally {
      await t.close();
    }
  });
});
