// src/evidence/r2-storage.ts
// Backward-compat re-export. The original v2 code used R2 for evidence
// storage. On the free tier, R2 requires a payment method on file (even
// though its 10 GB free tier is technically free), so we replaced it with
// D1 BLOB storage.
//
// All exports below delegate to src/evidence/d1-storage.ts. Existing
// callers (scan-runner, report-generator, api/routes/webhooks, etc.) keep
// their imports working without code changes.

export {
  storeEvidence,
  retrieveEvidence,
  signedEvidenceUrl,
  listEvidence,
  purgeExpiredEvidence,
  type StoreEvidenceOpts,
  type StoredEvidence,
  type EvidenceListOpts,
} from "./d1-storage.js";
