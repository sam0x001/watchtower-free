// test/jsdiff.test.ts
import { describe, it, expect } from "vitest";
import { extractEndpoints, extractScriptUrls } from "../src/modules/js-analyzer.js";

describe("JavaScript analysis", () => {
  it("extracts API endpoints from JS", () => {
    const js = `
      fetch("/api/v1/users");
      axios.post("/api/v2/login");
      const x = "/api/payments/charge";
      navigate("/admin/dashboard");
    `;
    const endpoints = extractEndpoints(js, "https://example.com/app.js");
    const paths = endpoints.map((e) => e.path);
    expect(paths).toContain("/api/v1/users");
    expect(paths).toContain("/api/v2/login");
    expect(paths).toContain("/api/payments/charge");
    expect(paths).toContain("/admin/dashboard");
  });

  it("extracts script URLs from HTML", () => {
    const html = new TextEncoder().encode(`
      <html>
      <head>
        <script src="/static/app.js"></script>
        <script src="https://cdn.example.com/lib.js"></script>
        <script>import "/static/module.js";</script>
      </head>
      </html>
    `);
    const urls = extractScriptUrls("https://example.com/", html);
    expect(urls).toContain("https://example.com/static/app.js");
    expect(urls).toContain("https://cdn.example.com/lib.js");
    expect(urls).toContain("https://example.com/static/module.js");
  });

  it("ignores external non-http schemes", () => {
    const html = new TextEncoder().encode(`<script src="javascript:alert(1)"></script>`);
    const urls = extractScriptUrls("https://example.com/", html);
    expect(urls).toHaveLength(0);
  });
});
