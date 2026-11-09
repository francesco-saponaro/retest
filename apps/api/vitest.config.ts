import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (pkg: string) => fileURLToPath(new URL(`../../packages/${pkg}/src/index.ts`, import.meta.url));

export default defineConfig({
  resolve: {
    // Tests run against the packages' source, so no build step is needed before `pnpm test`.
    alias: { "@retest/schema": src("schema"), "@retest/parsers": src("parsers") },
  },
  test: {
    name: "api",
    include: ["test/**/*.test.ts"],
    testTimeout: 20000,
    hookTimeout: 30000,
  },
});
