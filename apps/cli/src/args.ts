import { parseArgs } from "node:util";
import { TOOLS, type Tool } from "@retest/schema";

/**
 * The command line, read into one of five commands or an error to print. Nothing here talks to the
 * network or the disk, so every way of typing a command can be tested on its own.
 */
export type Command =
  | { kind: "help" }
  | { kind: "assessments" }
  | { kind: "new"; name: string; targets: string[]; exclusions: string[]; authorizedBy: string; client?: string }
  | { kind: "import"; tool: Exclude<Tool, "manual">; file: string; assessment: string; repository?: string }
  | { kind: "report"; assessment: string; summary: boolean; out?: string }
  | { kind: "error"; message: string };

const SCANNERS = TOOLS.filter((t): t is Exclude<Tool, "manual"> => t !== "manual");

export const USAGE = `Usage:
  retest assessments                                   list the assessments you can see
  retest new --name <name> --target <t> [--target <t>] [--exclude <x>] --authorized-by <who> [--client <c>]
                                                       create an assessment, print its id
  retest import --tool <tool> <file> --assessment <id> [--repository <name>]
                                                       import a scanner's output (${SCANNERS.join(", ")})
  retest report <id> [--summary] [--out <file>]        the technical report, or the executive summary, as markdown

Environment:
  RETEST_API_URL   where the API is (default http://127.0.0.1:3001)
  RETEST_TOKEN     a bearer token, from \`pnpm -C apps/api token <user>\``;

export function parseCommand(argv: string[]): Command {
  let parsed: ReturnType<typeof read>;
  try {
    parsed = read(argv);
  } catch (e) {
    return { kind: "error", message: e instanceof Error ? e.message : String(e) };
  }
  const { values: v, positionals: p } = parsed;
  const [name, ...rest] = p;
  if (v.help || name === undefined || name === "help") return { kind: "help" };

  switch (name) {
    case "assessments":
      return { kind: "assessments" };
    case "new": {
      if (!v.name) return { kind: "error", message: "new needs --name <name>" };
      if (!v.target?.length) return { kind: "error", message: "new needs at least one --target" };
      if (!v["authorized-by"]) return { kind: "error", message: "new needs --authorized-by <who signed the scope>" };
      return { kind: "new", name: v.name, targets: v.target, exclusions: v.exclude ?? [], authorizedBy: v["authorized-by"], ...(v.client ? { client: v.client } : {}) };
    }
    case "import": {
      const tool = SCANNERS.find((t: Exclude<Tool, "manual">) => t === v.tool);
      if (!tool) return { kind: "error", message: `--tool must be one of ${SCANNERS.join(", ")}` };
      if (!rest[0]) return { kind: "error", message: "import needs the file to read" };
      if (!v.assessment) return { kind: "error", message: "import needs --assessment <id>" };
      return { kind: "import", tool, file: rest[0], assessment: v.assessment, ...(v.repository ? { repository: v.repository } : {}) };
    }
    case "report": {
      if (!rest[0]) return { kind: "error", message: "report needs the assessment id" };
      return { kind: "report", assessment: rest[0], summary: v.summary ?? false, ...(v.out ? { out: v.out } : {}) };
    }
    default:
      return { kind: "error", message: `unknown command: ${name}` };
  }
}

function read(argv: string[]) {
  return parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: {
      help: { type: "boolean", short: "h" },
      tool: { type: "string" },
      assessment: { type: "string" },
      repository: { type: "string" },
      summary: { type: "boolean" },
      out: { type: "string", short: "o" },
      name: { type: "string" },
      target: { type: "string", multiple: true },
      exclude: { type: "string", multiple: true },
      client: { type: "string" },
      "authorized-by": { type: "string" },
    },
  });
}
