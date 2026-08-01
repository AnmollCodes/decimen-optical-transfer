// Separate from vite.config.ts so browser-only plugins (basicSsl) don't
// load inside the Node test runner.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    reporters: ["verbose"],
  },
});
