"""Shared fixtures: a fully wired in-memory stack (store + objects)."""

from __future__ import annotations

from pathlib import Path

import pytest

from aml_investigations.config import Settings
from aml_investigations.dispositions import DispositionService
from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.investigation import InvestigationService
from aml_investigations.models import Alert
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.sar import SarNarrativeService
from aml_investigations.screening import ListScreeningFeed, ScreeningService
from aml_investigations.stores import InMemoryCaseStore
from aml_investigations.transactions import ListRulePackFeed, ListTransactionFeed
from aml_investigations.typologies import TypologyService
from aml_investigations.wiring import Services
from aml_investigations.workflow import CaseWorkflow

SEED_ALERTS = [
    Alert(
        alert_id="ALRT-T-001",
        rule_id="TM-STRUCTURING-01",
        customer_id="CUST-1001",
        account_id="ACCT-5001",
        severity="high",
        detected_on="2026-10-20",
        summary="Deposits clustering under the CTR threshold.",
        transaction_refs=["TXN-1", "TXN-2"],
    ),
    Alert(
        alert_id="ALRT-T-002",
        rule_id="TM-VELOCITY-03",
        customer_id="CUST-1002",
        account_id="ACCT-5002",
        severity="medium",
        detected_on="2026-10-21",
        summary="Rapid in-out movement.",
    ),
]


@pytest.fixture()
def services(tmp_path: Path) -> Services:
    store = InMemoryCaseStore()
    objects = LocalObjectStore(tmp_path / "objects")
    evidence = EvidenceService(store, objects)
    workflow = CaseWorkflow(store, screening_store=store)
    feed = ListAlertFeed(list(SEED_ALERTS))
    intake = IntakeService(store, feed, evidence)
    screening = ScreeningService(store, store, evidence)
    typologies = TypologyService(store, store, evidence)
    investigations = InvestigationService(
        store, store, store, store, evidence, disposition_store=store
    )
    dispositions = DispositionService(store, store, store, store, evidence, workflow)
    sar = SarNarrativeService(store, store, store, store, evidence)
    settings = Settings(
        database_url=None,
        sqlite_path=tmp_path / "aml.db",
        migrations_dir=tmp_path,
        object_store_dir=tmp_path / "objects",
        s3_endpoint_url=None,
        s3_bucket="aml-evidence",
        seed_alerts_path=tmp_path / "seed.json",
        screening_lists_path=tmp_path / "lists.json",
        transaction_streams_path=tmp_path / "streams.json",
        typology_rules_path=tmp_path / "rules.json",
        log_level="INFO",
    )
    return Services(
        settings=settings,
        store=store,
        objects=objects,
        evidence=evidence,
        workflow=workflow,
        alerts=feed,
        intake=intake,
        screening=screening,
        screening_feed=ListScreeningFeed([]),
        transactions=ListTransactionFeed([], {}),
        typologies=typologies,
        rule_pack_feed=ListRulePackFeed([]),
        investigations=investigations,
        dispositions=dispositions,
        sar=sar,
    )
