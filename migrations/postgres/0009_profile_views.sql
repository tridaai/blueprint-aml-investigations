-- 0009 (postgres): KYC profile views (R11).
--
-- An assembled profile view is a derived artefact stored as an
-- append-only version row: content-addressed (the profile id
-- derives from the hash of the facts it was assembled from),
-- written once and never updated or deleted. Rebuilding over
-- unchanged inputs returns the stored row; changed inputs append
-- the next version alongside it. Full artefact payloads are
-- stored as JSON, the port's established pattern (0007/0008).

CREATE TABLE IF NOT EXISTS profile_views (
    profile_id  TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    version     INTEGER NOT NULL,
    assembled_at TIMESTAMPTZ NOT NULL,
    payload     JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_profile_views_customer
    ON profile_views (customer_id);
