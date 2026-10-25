-- Blueprint #15 R5: dispositions and confirmations (SQLite dialect).
-- A disposition record is the analyst gate's artefact: a named
-- analyst, a coded outcome, coded rationale from a versioned
-- vocabulary, and the investigation-record version relied on.
-- Records are append-only — a later disposition supersedes an
-- earlier one in the case view; no row is ever updated or deleted.
-- A confirmation is the second person's answer to a disposition
-- that required one (dual control at the gate): its own append-only
-- row, never an edit to the disposition it answers. Both records
-- are also held as hash-chained evidence items on the case.

CREATE TABLE IF NOT EXISTS dispositions (
    disposition_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dispositions_case ON dispositions (case_id);

CREATE TABLE IF NOT EXISTS disposition_confirmations (
    confirmation_id TEXT PRIMARY KEY,
    disposition_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_confirmations_case ON disposition_confirmations (case_id);
CREATE INDEX IF NOT EXISTS idx_confirmations_disposition ON disposition_confirmations (disposition_id);
