import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { testApp, type TestApp } from "../../api/test/app.js";
import { run, type Io } from "../src/run.js";

const fixtures = fileURLToPath(new URL("../../../packages/parsers/fixtures/", import.meta.url));

let t: TestApp;
let token: string;

beforeAll(async () => {
  t = await testApp();
  token = await t.token("francesco");
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  await t.reset();
});

/** The CLI's own code, with its requests answered by the API in memory instead of over a socket. */
function io(files: Record<string, string> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const written: Record<string, string> = {};
  const value: Io = {
    fetch: async (input, init) => {
      const url = new URL(String(input));
      const res = await t.app.inject({
        method: (init?.method ?? "GET") as "GET",
        url: url.pathname + url.search,
        headers: Object.fromEntries(new Headers(init?.headers).entries()),
        ...(init?.body ? { payload: String(init.body) } : {}),
      });
      const headers = new Headers();
      for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) headers.set(k, String(v));
      return new Response(res.statusCode === 204 ? null : res.body, { status: res.statusCode, headers });
    },
    readFile: async (path) => {
      if (path in files) return files[path]!;
      try {
        return readFileSync(join(fixtures, path), "utf8");
      } catch {
        throw Object.assign(new Error(`ENOENT: no such file or directory, open '${path}'`), { code: "ENOENT" });
      }
    },
    writeFile: async (path, text) => {
      written[path] = text;
    },
    out: (line) => out.push(line),
    err: (line) => err.push(line),
  };
  return { value, out, err, written };
}

const env = () => ({ RETEST_API_URL: "http://api.test", RETEST_TOKEN: token });

describe("retest, against the API", () => {
  it("creates an assessment, imports two scanner files into it and prints what each import did", async () => {
    const x = io();
    expect(await run(["new", "--name", "Juice Shop lab", "--target", "127.0.0.1", "--target", "http://127.0.0.1:3000", "--authorized-by", "francesco"], env(), x.value)).toBe(0);
    const id = x.out[0]!;
    expect(id).toMatch(/^a-/);
    expect(await run(["import", "--tool", "nmap", "nmap/juice-shop.xml", "--assessment", id], env(), x.value)).toBe(0);
    expect(x.out[1]).toBe("nmap nmap/juice-shop.xml: 4 parsed, 4 created, 0 merged, 1 asset created.");
    expect(await run(["import", "--tool", "nuclei", "nuclei/juice-shop.jsonl", "--assessment", id], env(), x.value)).toBe(0);
    expect(x.out[2]).toMatch(/^nuclei nuclei\/juice-shop\.jsonl: 11 parsed, \d+ created, \d+ merged, 1 asset created\.$/);
    expect(await run(["assessments"], env(), x.value)).toBe(0);
    expect(x.out[3]).toBe(`${id}  Juice Shop lab  scope  draft`);
  });

  it("prints the technical report, or writes the summary to a file", async () => {
    const id = await t.assessment("francesco", { name: "Juice Shop lab" });
    const x = io();
    await run(["import", "--tool", "zap", "zap/juice-shop.json", "--assessment", id], env(), x.value);
    expect(await run(["report", id], env(), x.value)).toBe(0);
    expect(x.out[1]).toMatch(/^# Juice Shop lab\n/);
    expect(await run(["report", id, "--summary", "--out", "summary.md"], env(), x.value)).toBe(0);
    expect(x.written["summary.md"]).toMatch(/^# Juice Shop lab: executive summary/);
    expect(x.out[2]).toBe("Wrote summary.md.");
  });

  it("says what the API refused, in the API's words, and exits 1", async () => {
    const x = io();
    expect(await run(["report", "a-not-there"], env(), x.value)).toBe(1);
    expect(x.err).toEqual(["retest: assessment not found (404)"]);
    const id = await t.assessment("someone-else");
    expect(await run(["import", "--tool", "nmap", "nmap/juice-shop.xml", "--assessment", id], env(), x.value)).toBe(1);
    expect(x.err[1]).toBe("retest: assessment not found (404)");
  });

  it("needs a token, reads no file it cannot find, and exits 2 on a usage error", async () => {
    const x = io();
    expect(await run(["assessments"], { RETEST_API_URL: "http://api.test" }, x.value)).toBe(2);
    expect(x.err[0]).toBe("retest: set RETEST_TOKEN to a token from `pnpm -C apps/api token <user>`");
    expect(await run(["import", "--tool", "nmap", "missing.xml", "--assessment", "a-1"], env(), x.value)).toBe(1);
    expect(x.err[1]).toBe("retest: cannot read missing.xml");
    expect(await run(["scan"], env(), x.value)).toBe(2);
    expect(x.err[2]).toBe("retest: unknown command: scan");
    expect(x.out.join("\n")).toMatch(/Usage:/);
  });

  it("prints help with every command", async () => {
    const x = io();
    expect(await run(["help"], {}, x.value)).toBe(0);
    const help = x.out.join("\n");
    for (const c of ["retest new", "retest import", "retest report", "retest assessments", "RETEST_API_URL", "RETEST_TOKEN"]) expect(help).toContain(c);
  });
});
