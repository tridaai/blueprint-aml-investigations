"""The SQL case store (SQLite profile) honours the same contract,
and the migration runner is idempotent."""

from __future__ import annotations

from pathlib import Path

from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.migrations import run_migrations
from aml_investigations.models import CaseStatus
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.stores import SqlCaseStore
from aml_investigations.workflow import CaseWorkflow
from tests.conftest import SEED_ALERTS

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_sqlite_store_round_trip(tmp_path):
    store = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
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

    reopened = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
    persisted = reopened.get_case(case.case_id)
    assert persisted is not None
    assert persisted.status is CaseStatus.ASSEMBLING
    assert reopened.get_case_by_alert("ALRT-T-001").case_id == case.case_id
    assert len(reopened.list_evidence(case.case_id)) == 2
    assert len(reopened.list_audit(case.case_id)) >= 3
    assert EvidenceService(reopened, objects).verify_chain(case.case_id) is True


def test_migrations_are_idempotent(tmp_path):
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "m.db"))
    first = run_migrations(conn, REPO_ROOT / "migrations", "sqlite", "qmark")
    second = run_migrations(conn, REPO_ROOT / "migrations", "sqlite", "qmark")
    assert first == ["0001", "0002", "0003", "0004", "0005", "0006", "0007"]
    assert second == []
