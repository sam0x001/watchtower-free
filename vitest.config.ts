// vitest.config.ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    setupFiles: ["./test/setup.ts"],
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      exclude: ["test/**", "**/*.d.ts"],
    },
  },
  resolve: {
    alias: {
      "@": "/home/z/my-project/watchtower/src",
    },
  },
});
