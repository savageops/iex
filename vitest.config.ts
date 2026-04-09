import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    setupFiles: ["tests/setup.ts"],
    testTimeout: 60_000,
    hookTimeout: 120_000,
    reporters: ["default"],
    sequence: {
      concurrent: false,
    },
    env: {
      IEX_BENCH_DATA: "tools/data/corpus",
      IEX_BENCH_PROFILE: "debug",
    },
  },
});
