import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

/** The packages are resolved from source, as the API's own tests do, so nothing needs building first. */
export const aliases = [
  { find: "@retest/schema", replacement: here("../../packages/schema/src/index.ts") },
  { find: "@retest/parsers", replacement: here("../../packages/parsers/src/index.ts") },
  { find: /^@retest\/api\/(.*)$/, replacement: `${here("../api/src/")}$1` },
];

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: aliases },
  optimizeDeps: {
    // PGlite loads its own WebAssembly and workers; pre-bundling breaks those paths.
    exclude: ["@electric-sql/pglite"],
  },
  server: {
    // In development the app talks to the API through the dev server, so no CORS is needed on the API.
    proxy: {
      "/api": { target: "http://127.0.0.1:3001", changeOrigin: false, rewrite: (p) => p.replace(/^\/api/, "") },
    },
  },
  build: { target: "es2022" },
});
