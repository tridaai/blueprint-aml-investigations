-- Blueprint #15 R3: typology store (PostgreSQL dialect).
-- Rule packs are immutable once registered (Law 4): the (pack_id,
-- version) pair is unique and there is no update path for the table.
-- Transactions arrive only through evidence-backed batch ingestion
-- and are appended, never edited; findings are append-only records
-- of what a run computed under a named pack version.

CREATE TABLE IF NOT EXISTS rule_packs (
    pack_id TEXT NOT NULL,
    version TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (pack_id, version)
);

CREATE TABLE IF NOT EXISTS account_profiles (
    account_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transaction_batches (
    batch_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    evidence_seq INTEGER,
    payload TEXT NOT NULL,
    UNIQUE (case_id, content_sha256)
);

CREATE INDEX IF NOT EXISTS idx_batches_case ON transaction_batches (case_id);

CREATE TABLE IF NOT EXISTS transactions (
    transaction_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    posted_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (case_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_transactions_case ON transactions (case_id);

CREATE TABLE IF NOT EXISTS typology_runs (
    run_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    rule_pack_id TEXT NOT NULL,
    rule_pack_version TEXT NOT NULL,
    input_fingerprint TEXT NOT NULL,
    run_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_truns_case ON typology_runs (case_id);

CREATE TABLE IF NOT EXISTS typology_findings (
    finding_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    typology_id TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_case ON typology_findings (case_id);
