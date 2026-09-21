// test/setup.ts — vitest setup
import { beforeEach, vi } from "vitest";

// Provide a minimal Web Crypto polyfill behavior (Workers runtime already has it).
beforeEach(() => {
  vi.clearAllMocks();
});
