-- 0011 (sqlite): the model cost ledger (R13).
--
-- Every call through the model gateway appends one call entry:
-- case, purpose, profile, model, tokens, the price-table version
-- and unit prices it was priced with, and the exact Decimal cost.
-- Append-only — a later price-table version prices future calls;
-- it never reprices recorded ones. Budget events record per-case
-- cap refusals the same way. Full artefact payloads are stored as
-- JSON, the port's established pattern (0007-0010).

CREATE TABLE IF NOT EXISTS model_call_ledger (
    entry_id            TEXT PRIMARY KEY,
    case_id             TEXT,
    purpose             TEXT NOT NULL,
    profile_id          TEXT NOT NULL,
    model               TEXT NOT NULL,
    price_table_version TEXT NOT NULL,
    called_at           TEXT NOT NULL,
    payload             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_model_call_ledger_case
    ON model_call_ledger (case_id);
CREATE INDEX IF NOT EXISTS ix_model_call_ledger_called
    ON model_call_ledger (called_at);

CREATE TABLE IF NOT EXISTS model_budget_events (
    event_id    TEXT PRIMARY KEY,
    case_id     TEXT NOT NULL,
    profile_id  TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_model_budget_events_case
    ON model_budget_events (case_id);
