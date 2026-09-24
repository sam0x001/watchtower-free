// vitest.config.ts
//
// Two things matter here:
//   1. the "@/*" alias must resolve to this repo's src/ (the previous Linux
//      path from the upstream template was unusable on Windows);
//   2. the bundled wordlists are imported as text modules
//      (`import fuzzTxt from "../../fuzz-wordlists/fuzz.txt"`), which Wrangler
//      does natively — Vitest needs this tiny plugin to do the same.

import { defineConfig, type Plugin } from "vitest/config";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";

/**
 * Load any *.txt import as a module whose default export is the file content.
 * (Vite otherwise classifies .txt as a static asset and emits an URL string.)
 * Must run in `load` with `enforce: "pre"` to beat the builtin asset plugin.
 */
function txtAsModule(): Plugin {
  return {
    name: "watchtower-txt-as-module",
    enforce: "pre",
    async load(id) {
      const file = id.split("?")[0]!;
      if (!file.endsWith(".txt")) return null;
      const text = await readFile(file, "utf8");
      return { code: `export default ${JSON.stringify(text)};`, map: null };
    },
  };
}

export default defineConfig({
  plugins: [txtAsModule()],
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
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
});

