-- Blueprint #15 R1: case store schema (SQLite dialect).
-- Payloads are JSON text in both dialects; the filterable columns the
-- queue views and regulatory clocks need are broken out alongside.

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL UNIQUE,
    customer_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    detected_on TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cases_status ON cases (status);
CREATE INDEX IF NOT EXISTS idx_cases_detected_on ON cases (detected_on);

CREATE TABLE IF NOT EXISTS evidence_items (
    case_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    chain_hash TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (case_id, seq)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_events (case_id);
