import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** Read a file from `packages/parsers/fixtures/`. */
export function fixture(path: string): string {
  return readFileSync(join(here, "..", "fixtures", path), "utf8");
}
