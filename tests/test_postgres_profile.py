"""R16: the Postgres profile, tested against a real server.

These tests are skipped unless ``AML_TEST_DATABASE_URL`` names a
reachable Postgres (the parity database stood up for the round —
see tests/pg_parity.py). They grade the parts of the production
profile the parity run cannot reach by construction:

- the migration runner against the postgres dialect on an EMPTY
  database: every migration applies, in order, and a second run
  applies nothing (the runner's behaviour on PG is itself graded,
  not just the store's);
- ``SqlCaseStore.postgres`` — the exact construction production
  wiring uses — persisting a case across connections, migrations
  included: reopening a migrated database must not re-apply or
  fail (a dict-row connection reads its own migration ledger).

Fresh databases are created per test (UTF8, template0) and dropped
afterwards, so the tests are re-runnable against any empty server.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
import pytest

from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.migrations import run_migrations
from aml_investigations.models import CaseStatus
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.stores import SqlCaseStore
from aml_investigations.workflow import CaseWorkflow
from tests.conftest import SEED_ALERTS
from tests.pg_parity import MIGRATIONS_DIR, parity_url

REPO_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    not parity_url(),
    reason="AML_TEST_DATABASE_URL not set — no Postgres to test against",
)

EXPECTED_VERSIONS = [
    "0001",
    "0002",
    "0003",
    "0004",
    "0005",
    "0006",
    "0007",
    "0008",
    "0009",
    "0010",
    "0011",
]


def _fresh_database() -> tuple[str, str]:
    """Create an empty database on the parity server; return (name, dsn)."""
    base = parity_url()
    assert base is not None
    name = f"aml_t_{uuid.uuid4().hex[:16]}"
    admin = psycopg.connect(base, autocommit=True)
    try:
        admin.execute(
            f'CREATE DATABASE "{name}" TEMPLATE template0 ENCODING \'UTF8\''
        )
    finally:
        admin.close()
    dsn = base.rsplit("/", 1)[0] + f"/{name}"
    return name, dsn


def _drop_database(name: str) -> None:
    base = parity_url()
    assert base is not None
    admin = psycopg.connect(base, autocommit=True)
    try:
        admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
            " WHERE datname = %s AND pid <> pg_backend_pid()",
            (name,),
        )
        admin.execute(f'DROP DATABASE IF EXISTS "{name}"')
    finally:
        admin.close()


@pytest.fixture()
def fresh_db():
    name, dsn = _fresh_database()
    yield dsn
    _drop_database(name)


def test_postgres_migrations_apply_fresh_and_rerun_clean(fresh_db):
    conn = psycopg.connect(fresh_db)
    try:
        first = run_migrations(conn, REPO_ROOT / "migrations", "postgres", "format")
        assert first == EXPECTED_VERSIONS
        second = run_migrations(conn, REPO_ROOT / "migrations", "postgres", "format")
        assert second == []
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT table_name FROM information_schema.tables"
                " WHERE table_schema = 'public'"
            ).fetchall()
        }
        # One table family per migration era, first to last.
        for expected in (
            "cases",
            "evidence_items",
            "list_snapshots",
            "typology_runs",
            "investigation_records",
            "dispositions",
            "sar_narratives",
            "continuing_reviews",
            "profile_views",
            "media_assessments",
            "model_call_ledger",
        ):
            assert expected in tables, f"missing table {expected}"
    finally:
        conn.close()


def test_postgres_store_persists_across_connections(fresh_db, tmp_path):
    store = SqlCaseStore.postgres(fresh_db, REPO_ROOT / "migrations")
    objects = LocalObjectStore(tmp_path / "objects")
    evidence = EvidenceService(store, objects)
    workflow = CaseWorkflow(store)
    intake = IntakeService(store, ListAlertFeed(list(SEED_ALERTS)), evidence)

    case = intake.open_case("ALRT-T-001")
    evidence.add_item(
        case.case_id,
        kind="kyc_profile",
        content=b'{"customer_id": "CUST-1001"}',
        source_ref="kyc:CUST-1001",
        captured_by="evidence-service",
    )
    workflow.transition(case.case_id, CaseStatus.ASSEMBLING, actor="svc")

    # A second construction on the same database: migrations must
    # no-op (not fail, not re-apply) and the case must be intact.
    reopened = SqlCaseStore.postgres(fresh_db, REPO_ROOT / "migrations")
    persisted = reopened.get_case(case.case_id)
    assert persisted is not None
    assert persisted.status is CaseStatus.ASSEMBLING
    assert reopened.get_case_by_alert("ALRT-T-001").case_id == case.case_id
    assert len(reopened.list_evidence(case.case_id)) == 2
    assert EvidenceService(reopened, objects).verify_chain(case.case_id) is True
