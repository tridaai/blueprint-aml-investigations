-- Blueprint #15 R7: dual-control SAR approvals, case seals,
-- unseals, and legal-hold events (PostgreSQL dialect).
-- All four are append-only custody records. An approval decides
-- exactly one narrative version and is never edited (a rejection
-- is answered by a re-draft, a new version with its own decision).
-- A seal is never edited or deleted either: an unseal is a
-- separate record that lifts it, a reseal is the next seal
-- version, and a case's sealed and legal-hold states are derived
-- from these histories, never stored as mutable flags. Each
-- record is also held as a hash-chained evidence item on the case
-- (kinds 'sar_approval', 'case_seal', 'case_unseal', 'legal_hold').

CREATE TABLE IF NOT EXISTS sar_approvals (
    approval_id TEXT PRIMARY KEY,
    narrative_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sar_approvals_case ON sar_approvals (case_id);
CREATE INDEX IF NOT EXISTS idx_sar_approvals_narrative ON sar_approvals (narrative_id);

CREATE TABLE IF NOT EXISTS case_seals (
    seal_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    sealed_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE (case_id, version)
);

CREATE INDEX IF NOT EXISTS idx_case_seals_case ON case_seals (case_id);

CREATE TABLE IF NOT EXISTS case_unseals (
    unseal_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    seal_id TEXT NOT NULL,
    unsealed_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_case_unseals_case ON case_unseals (case_id);

CREATE TABLE IF NOT EXISTS legal_hold_events (
    hold_event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_legal_hold_events_case ON legal_hold_events (case_id);
