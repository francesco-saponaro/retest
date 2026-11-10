import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";
import { aliases } from "./vite.config.js";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: aliases },
  test: {
    name: "web",
    include: ["test/**/*.test.{ts,tsx}"],
    environment: "jsdom",
    setupFiles: ["test/setup.ts"],
    testTimeout: 30000,
    hookTimeout: 60000,
  },
});
