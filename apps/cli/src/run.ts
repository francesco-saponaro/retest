import { USAGE, parseCommand, type Command } from "./args.js";

/** Everything the command line touches outside itself, passed in so the tests can run it against the API in memory. */
export interface Io {
  fetch: typeof fetch;
  readFile: (path: string) => Promise<string>;
  writeFile: (path: string, text: string) => Promise<void>;
  out: (line: string) => void;
  err: (line: string) => void;
}

export type Env = Record<string, string | undefined>;

class Refused extends Error {}

interface ImportOut {
  tool: string;
  filename: string | null;
  parsed: number;
  created: number;
  merged: number;
  assetsCreated: number;
  warnings: string[];
}

interface AssessmentOut {
  id: string;
  name: string;
  phase: string;
  status: string;
}

const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? "" : "s"}`;

/** Run one command. Returns the exit code: 0 done, 1 the API or the disk said no, 2 the command was wrong. */
export async function run(argv: string[], env: Env, io: Io): Promise<number> {
  const command = parseCommand(argv);
  if (command.kind === "help") {
    io.out(USAGE);
    return 0;
  }
  if (command.kind === "error") {
    io.err(`retest: ${command.message}`);
    io.out(USAGE);
    return 2;
  }
  const token = env.RETEST_TOKEN;
  if (!token) {
    io.err("retest: set RETEST_TOKEN to a token from `pnpm -C apps/api token <user>`");
    return 2;
  }
  const base = (env.RETEST_API_URL || "http://127.0.0.1:3001").replace(/\/$/, "");
  try {
    await execute(command, base, token, io);
    return 0;
  } catch (e) {
    io.err(`retest: ${e instanceof Refused ? e.message : e instanceof Error ? e.message : String(e)}`);
    return 1;
  }
}

async function call(io: Io, base: string, token: string, path: string, init: { method?: string; body?: unknown; accept?: string } = {}): Promise<Response> {
  const headers: Record<string, string> = { authorization: `Bearer ${token}`, accept: init.accept ?? "application/json" };
  if (init.body !== undefined) headers["content-type"] = "application/json";
  const res = await io.fetch(`${base}${path}`, { method: init.method ?? "GET", headers, ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}) });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: unknown; issues?: { path?: string; message?: string }[] };
    const reason = typeof body.error === "string" ? body.error : "request failed";
    const issues = Array.isArray(body.issues) ? body.issues.map((i) => `${i.path ? `${i.path} ` : ""}${i.message ?? ""}`.trim()).filter(Boolean) : [];
    throw new Refused(`${reason}${issues.length ? `: ${issues.join("; ")}` : ""} (${res.status})`);
  }
  return res;
}

async function execute(command: Exclude<Command, { kind: "help" } | { kind: "error" }>, base: string, token: string, io: Io): Promise<void> {
  const id = encodeURIComponent;
  switch (command.kind) {
    case "assessments": {
      const { items } = (await (await call(io, base, token, "/assessments")).json()) as { items: AssessmentOut[] };
      for (const a of items) io.out(`${a.id}  ${a.name}  ${a.phase}  ${a.status}`);
      return;
    }
    case "new": {
      const body = {
        name: command.name,
        ...(command.client ? { client: command.client } : {}),
        scope: { targets: command.targets, exclusions: command.exclusions, authorizedBy: command.authorizedBy, authorizedAt: new Date().toISOString() },
      };
      const a = (await (await call(io, base, token, "/assessments", { method: "POST", body })).json()) as AssessmentOut;
      io.out(a.id);
      return;
    }
    case "import": {
      let content: string;
      try {
        content = await io.readFile(command.file);
      } catch {
        throw new Refused(`cannot read ${command.file}`);
      }
      const body = { assessmentId: command.assessment, tool: command.tool, content, filename: command.file.slice(-300), ...(command.repository ? { repository: command.repository } : {}) };
      const r = (await (await call(io, base, token, "/imports", { method: "POST", body })).json()) as ImportOut;
      io.out(`${r.tool} ${r.filename ?? command.file}: ${r.parsed} parsed, ${r.created} created, ${r.merged} merged, ${plural(r.assetsCreated, "asset")} created.`);
      for (const w of r.warnings) io.err(`warning: ${w}`);
      return;
    }
    case "report": {
      const text = await (await call(io, base, token, `/assessments/${id(command.assessment)}/${command.summary ? "summary" : "report"}.md`, { accept: "text/markdown" })).text();
      if (command.out) {
        await io.writeFile(command.out, text);
        io.out(`Wrote ${command.out}.`);
      } else io.out(text);
      return;
    }
  }
}
