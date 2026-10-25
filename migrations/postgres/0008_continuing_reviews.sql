-- 0008 (postgres): continuing-activity reviews (R9).
--
-- The review artefact and its disposition are append-only rows,
-- written once and never updated or deleted: a review assembled
-- over a superseded record stands in place and a fresh review is
-- opened in its stead, and a dispositioned review is the cycle's
-- permanent record. The clock service reads these rows to learn
-- a cycle's outcome — the disposition row, and nothing else,
-- answers the clock. Full artefact payloads are stored as JSON,
-- the port's established pattern (0007).

CREATE TABLE IF NOT EXISTS continuing_reviews (
    review_id   TEXT PRIMARY KEY,
    case_id     TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    cycle       INTEGER NOT NULL,
    opened_at   TIMESTAMPTZ NOT NULL,
    payload     JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_continuing_reviews_case
    ON continuing_reviews (case_id);
CREATE INDEX IF NOT EXISTS ix_continuing_reviews_customer
    ON continuing_reviews (customer_id);

CREATE TABLE IF NOT EXISTS continuing_review_dispositions (
    review_disposition_id TEXT PRIMARY KEY,
    review_id   TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    decided_at  TIMESTAMPTZ NOT NULL,
    payload     JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_continuing_review_dispositions_case
    ON continuing_review_dispositions (case_id);
CREATE INDEX IF NOT EXISTS ix_continuing_review_dispositions_review
    ON continuing_review_dispositions (review_id);
CREATE INDEX IF NOT EXISTS ix_continuing_review_dispositions_customer
    ON continuing_review_dispositions (customer_id);
