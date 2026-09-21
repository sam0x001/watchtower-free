-- 0011_evidence_d1.sql
-- D1-backed evidence storage — replaces R2 for the free tier.
--
-- R2 requires a payment method on file even though its free tier is
-- technically 10 GB at $0. D1's free tier (5 GB) requires no payment method.
-- Since all evidence is AES-GCM encrypted before storage, storing it as
-- TEXT in a D1 table is fine.
--
-- This table mirrors the schema of the old R2 object metadata + the
-- legacy `finding_evidence` table (which is kept for backward compat
-- with API consumers that join on it).

CREATE TABLE IF NOT EXISTS evidence_blobs (
  id              TEXT PRIMARY KEY,
  r2_key          TEXT UNIQUE NOT NULL,    -- kept as the lookup key for backward compat
  organization_id  TEXT NOT NULL,
  target_id       TEXT NOT NULL,
  finding_id      TEXT,
  evidence_type   TEXT NOT NULL,
  evidence_hash   TEXT NOT NULL,
  encrypted_blob  TEXT NOT NULL,           -- AES-GCM ciphertext as JSON-serialized blob
  redacted        INTEGER NOT NULL DEFAULT 1 CHECK (redacted IN (0,1)),
  description     TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL,
  accessed_at     TEXT,
  access_count    INTEGER NOT NULL DEFAULT 0,
  expires_at      TEXT NOT NULL             -- ISO timestamp — retention enforcement
);

CREATE INDEX IF NOT EXISTS idx_evidence_org ON evidence_blobs (organization_id, created_at);
CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence_blobs (target_id, created_at);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence_blobs (finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_expiry ON evidence_blobs (expires_at);
