// src/modules/report-generator.ts
// Generates reports in Markdown / JSON / HackerOne / Bugcrowd / internal /
// executive formats. Sensitive values are redacted before output.

import type { Env } from "../env.js";
import { redactSync } from "../security/redaction.js";
import type { Finding, Target } from "../types.js";
import { randomId } from "../crypto/hash.js";
import { sha256 } from "../crypto/hash.js";

export interface ReportInputs {
  target: Target;
  findings: Finding[];
  format: "markdown" | "json" | "pdf" | "hackerone" | "bugcrowd" | "internal" | "executive";
  methodology: string;
  tools: string[];
  limitations: string[];
  scopeText: string;
  authorized: boolean;
}

export interface GeneratedReport {
  id: string;
  r2Key: string;
  format: string;
  content: string;
  contentHash: string;
  findingsCount: number;
  createdAt: string;
}

export async function generateReport(env: Env, inputs: ReportInputs): Promise<GeneratedReport> {
  const id = randomId("rep", 12);
  const content = buildContent(inputs);
  const { redacted } = redactSync(content);
  const contentHash = await sha256(redacted);
  const r2Key = `reports/${inputs.target.organization_id}/${inputs.target.id}/${id}.${inputs.format === "json" ? "json" : "md"}`;

  // Use R2 if bound, otherwise fall back to D1 evidence_blobs.
  if (env.EVIDENCE) {
    await env.EVIDENCE.put(r2Key, redacted, {
      customMetadata: {
        "report-id": id,
        "target-id": inputs.target.id,
        "format": inputs.format,
        "content-hash": contentHash,
        "generated-at": new Date().toISOString(),
      },
    });
  } else {
    // D1 fallback — store the report content as an encrypted evidence blob.
    const { encryptString } = await import("../crypto/encryption.js");
    const encrypted = await encryptString(redacted, env.ENCRYPTION_KEY);
    await env.DB
      .prepare(`INSERT INTO evidence_blobs (id, r2_key, organization_id, target_id, finding_id, evidence_type, evidence_hash, encrypted_blob, redacted, description, created_at, accessed_at, access_count, expires_at) VALUES (?, ?, ?, ?, NULL, 'scanner_output', ?, ?, 0, ?, ?, NULL, 0, ?)`)
      .bind(
        `rep_${id}`,
        r2Key,
        inputs.target.organization_id,
        inputs.target.id,
        contentHash,
        encrypted,
        `Report ${inputs.format} for target ${inputs.target.id}`,
        new Date().toISOString(),
        new Date(Date.now() + 365 * 86_400_000).toISOString(),  // 1-year retention for reports
      )
      .run();
  }

  await env.DB
    .prepare(`UPDATE reports SET r2_key = ?, size_bytes = ?, methodology = ? WHERE id = ?`)
    .bind(r2Key, redacted.length, inputs.methodology, id)
    .run()
    .catch(() => undefined);

  await env.DB
    .prepare(`INSERT INTO reports (id, report_ref, organization_id, target_id, report_type, format, title, status, r2_key, content_hash, size_bytes, finding_ids, methodology, limitations, created_at, updated_at) VALUES (?, ?, ?, ?, 'technical_appendix', ?, ?, 'ready', ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, id, inputs.target.organization_id, inputs.target.id, inputs.format, `Report for ${inputs.target.name}`, r2Key, contentHash, redacted.length, JSON.stringify(inputs.findings.map((f) => f.id)), inputs.methodology, JSON.stringify(inputs.limitations), new Date().toISOString(), new Date().toISOString())
    .run()
    .catch(() => undefined);

  return {
    id,
    r2Key,
    format: inputs.format,
    content: redacted,
    contentHash,
    findingsCount: inputs.findings.length,
    createdAt: new Date().toISOString(),
  };
}

function buildContent(inputs: ReportInputs): string {
  const now = new Date().toISOString();
  const header =
`# Watchtower Security Report

- Target: ${inputs.target.name}
- Target ID: ${inputs.target.id}
- Organization ID: ${inputs.target.organization_id}
- Authorization Reference: ${inputs.target.authorization_reference}
- Authorization Expiry: ${inputs.target.authorization_expires_at}
- Report Format: ${inputs.format}
- Generated At: ${now}

## Scope
${inputs.scopeText}

## Methodology
${inputs.methodology}

## Tools and Versions
${inputs.tools.map((t) => `- ${t}`).join("\n")}

## Limitations
${inputs.limitations.map((l) => `- ${l}`).join("\n")}

## Disclosure Warning
This report contains confidential security information. Do not redistribute
outside of the authorized recipient list. All secrets have been redacted;
never include unredacted credentials in external communications.

## Affected Assets and Findings

`;

  const findingSections = inputs.findings.map((f) => formatFinding(f, inputs.format));
  const summary = `
## Summary
- Total findings: ${inputs.findings.length}
- Critical: ${inputs.findings.filter((f) => f.severity === "critical").length}
- High: ${inputs.findings.filter((f) => f.severity === "high").length}
- Medium: ${inputs.findings.filter((f) => f.severity === "medium").length}
- Low: ${inputs.findings.filter((f) => f.severity === "low").length}
- Informational: ${inputs.findings.filter((f) => f.severity === "informational").length}
`;

  return header + summary + findingSections.join("\n\n");
}

function formatFinding(f: Finding, fmt: string): string {
  const base = `### [${f.severity.toUpperCase()}] ${f.title}

- Finding ID: ${f.id}
- Type: ${f.type}
- Severity: ${f.severity}
- CVSS: ${f.cvss_score ?? "n/a"} (${f.cvss_vector ?? ""})
- EPSS: ${f.epss_score ?? "n/a"}
- CWE: ${f.cwe ?? "n/a"}
- CVE: ${f.cve ?? "n/a"}
- OWASP: ${f.owasp_category ?? "n/a"}
- Affected: ${f.affected_url ?? "n/a"}
- Confidence: ${f.confidence}
- Status: ${f.status}
- Verification: ${f.verification_state}

#### Summary
${f.summary}

#### Technical Description
${f.technical_description}

#### Business Impact
${f.business_impact ?? "Not yet assessed."}

#### Remediation
${f.remediation ?? "Pending."}

#### Detection
- Source: ${f.detection_source}
- Method: ${f.detection_method}
- First seen: ${f.first_seen}
- Last seen: ${f.last_seen}

#### Evidence Hashes
- (Evidence references are stored encrypted in R2. Access requires authorization.)
`;
  if (fmt === "hackerone") {
    return base + `\n#### HackerOne Submission Notes\n- Summary line: ${f.title}\n- Severity: ${f.severity} (CVSS ${f.cvss_score ?? "n/a"})\n- Steps to reproduce require manual verification before submission.\n`;
  }
  if (fmt === "bugcrowd") {
    return base + `\n#### Bugcrowd Submission Notes\n- Title: ${f.title}\n- Severity: ${f.severity}\n- Reproduce manually before submitting via Bugcrowd.\n`;
  }
  if (fmt === "executive") {
    return `### [${f.severity.toUpperCase()}] ${f.title}\n\n${f.summary}\nBusiness impact: ${f.business_impact ?? "Pending."}\n`;
  }
  return base;
}
