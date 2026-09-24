// test/notification-format.test.ts
// Telegram alert rendering: severity header, HTML escaping, no dead commands.

import { describe, it, expect } from "vitest";
import { formatTelegramAlert } from "../src/queues/notification-dispatcher.js";

describe("formatTelegramAlert", () => {
  it("renders a severity header with the matching emoji", () => {
    const message = formatTelegramAlert("critical", { title: "Exposed .env", summary: "body" });
    expect(message).toContain("🚨");
    expect(message).toContain("<b>[CRITICAL] Exposed .env</b>");
    expect(message).toContain("body");
  });

  it("falls back to an informational header for unknown severities", () => {
    const message = formatTelegramAlert("wat", { title: "Something" });
    expect(message).toContain("📌");
    expect(message).toContain("[WAT]");
  });

  it("escapes HTML in titles and summaries", () => {
    const message = formatTelegramAlert("high", {
      title: "<script>alert(1)</script>",
      summary: "a & b <b>bold</b>",
    });
    expect(message).not.toContain("<script>");
    expect(message).toContain("&lt;script&gt;");
    expect(message).toContain("a &amp; b &lt;b&gt;bold&lt;/b&gt;");
  });

  it("includes the target, change type and finding id when present", () => {
    const message = formatTelegramAlert("medium", {
      title: "New subdomain discovered: api.example.com",
      summary: "CT logs",
      target_name: "example.com",
      change_type: "new_subdomain",
      finding_id: "FND_123",
    });
    expect(message).toContain("<b>Target:</b> example.com");
    expect(message).toContain("<b>Change type:</b> <code>new_subdomain</code>");
    expect(message).toContain("<b>Finding ID:</b> <code>FND_123</code>");
  });

  it("does not reference removed commands", () => {
    const message = formatTelegramAlert("low", { title: "t", summary: "s" });
    expect(message).not.toContain("/diff_latest");
    expect(message).not.toContain("/finding_details");
  });
});
