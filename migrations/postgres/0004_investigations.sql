-- Blueprint #15 R4: investigation records (PostgreSQL dialect).
-- An investigation record is one version of a case's investigation:
-- cited findings, the working hypothesis, the counter-evidence
-- search, and the open questions. Records are append-only versions
-- — a re-investigation adds the next version and supersedes the
-- previous by pointer; no version is ever updated or deleted. The
-- record's full payload is also held as a hash-chained evidence
-- item (kind 'investigation_record') on the case.

CREATE TABLE IF NOT EXISTS investigation_records (
    record_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE (case_id, version)
);

CREATE INDEX IF NOT EXISTS idx_inv_records_case ON investigation_records (case_id);
