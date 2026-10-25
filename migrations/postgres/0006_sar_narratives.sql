-- Blueprint #15 R6: SAR narrative drafts and citation-verification
-- runs (PostgreSQL dialect).
-- A narrative draft is an append-only artefact version: it pins the
-- investigation record and the escalate_sar disposition it was
-- drafted from, and a re-draft is the next version — no row is ever
-- updated or deleted. Standing (draft / verified / stale /
-- superseded) is derived from the version chain, the record
-- versions, and the verification runs, never stored as an edit.
-- A verification run is the citation verifier's per-statement
-- verdict record over one narrative version; runs are append-only
-- too, the latest run for a narrative being the operative one.
-- Both artefacts are also held as hash-chained evidence items on
-- the case (kinds 'sar_narrative' and 'sar_narrative_verification').

CREATE TABLE IF NOT EXISTS sar_narratives (
    narrative_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE (case_id, version)
);

CREATE INDEX IF NOT EXISTS idx_sar_narratives_case ON sar_narratives (case_id);

CREATE TABLE IF NOT EXISTS sar_narrative_verifications (
    verification_id TEXT PRIMARY KEY,
    narrative_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    all_verified INTEGER NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sar_verifications_case ON sar_narrative_verifications (case_id);
CREATE INDEX IF NOT EXISTS idx_sar_verifications_narrative ON sar_narrative_verifications (narrative_id);
