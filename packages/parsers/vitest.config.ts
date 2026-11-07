import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    // Tests run against the schema's source, so no build step is needed before `pnpm test`.
    alias: { "@retest/schema": fileURLToPath(new URL("../schema/src/index.ts", import.meta.url)) },
  },
  test: {
    name: "parsers",
    include: ["test/**/*.test.ts"],
  },
});
