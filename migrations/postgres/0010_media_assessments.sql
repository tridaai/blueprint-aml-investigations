-- 0010 (postgres): adverse-media assessments (R12).
--
-- An assessment is the scorer's recorded verdict on one article
-- against one case's subject: append-only, written once and never
-- updated or deleted. A re-assessment under a newer scorer is a
-- new row alongside the earlier one. Full artefact payloads are
-- stored as JSON, the port's established pattern (0007-0009).

CREATE TABLE IF NOT EXISTS media_assessments (
    assessment_id TEXT PRIMARY KEY,
    case_id       TEXT NOT NULL,
    customer_id   TEXT NOT NULL,
    article_id    TEXT NOT NULL,
    band          TEXT NOT NULL,
    assessed_at   TIMESTAMPTZ NOT NULL,
    payload       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_media_assessments_case
    ON media_assessments (case_id);
