-- Blueprint #15 R2: screening snapshots, runs, and hits (SQLite dialect).
-- Snapshots are immutable once ingested (Law 3): the (list_kind, version)
-- pair is unique and the service refuses conflicting re-ingest — there is
-- no update path for this table anywhere in the codebase.

CREATE TABLE IF NOT EXISTS list_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    list_kind TEXT NOT NULL,
    version TEXT NOT NULL,
    published_at TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE (list_kind, version)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_kind ON list_snapshots (list_kind);

CREATE TABLE IF NOT EXISTS screening_runs (
    run_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    run_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runs_case ON screening_runs (case_id);

CREATE TABLE IF NOT EXISTS screening_hits (
    hit_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    list_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hits_case ON screening_hits (case_id);
