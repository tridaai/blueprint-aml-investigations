"""Shared fixtures: a fully wired in-memory stack (store + objects).

R16: when ``AML_TEST_DATABASE_URL`` is set, the whole suite runs
against Postgres instead — see tests/pg_parity.py. Activation
happens after collection, when every test module has imported its
store names; the fixtures below then build on Postgres stores
without knowing it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import pg_parity


def pytest_collection_modifyitems(session, config, items):
    pg_parity.activate()


def pytest_sessionfinish(session, exitstatus):
    pg_parity.cleanup()

from aml_investigations.approval import SarApprovalService
from aml_investigations.clocks import RegulatoryClockService
from aml_investigations.config import Settings
from aml_investigations.dispositions import DispositionService
from aml_investigations.evidence import EvidenceService
from aml_investigations.gateway import ModelGateway, default_gateway_config
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.investigation import InvestigationService
from aml_investigations.media import AdverseMediaService, ListMediaFeed
from aml_investigations.models import Alert
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.profiles import ProfileService
from aml_investigations.quarantine import QuarantineService
from aml_investigations.reporting import ReportingService
from aml_investigations.reviews import ContinuingReviewService
from aml_investigations.sar import SarNarrativeService
from aml_investigations.screening import ListScreeningFeed, ScreeningService
from aml_investigations.sealing import CaseSealingService
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
    evidence = EvidenceService(store, objects, seal_store=store)
    quarantine = QuarantineService(store, evidence, seal_store=store)
    evidence.quarantine = quarantine
    gateway = ModelGateway(
        default_gateway_config(), store, audit_store=store, evidence=evidence
    )
    workflow = CaseWorkflow(store, screening_store=store)
    feed = ListAlertFeed(list(SEED_ALERTS))
    clocks = RegulatoryClockService(
        store, store, store, evidence, approvals=store, review_store=store
    )
    intake = IntakeService(
        store, feed, evidence, clock_service=clocks, quarantine=quarantine
    )
    screening = ScreeningService(
        store, store, evidence, seal_store=store, quarantine=quarantine
    )
    typologies = TypologyService(
        store, store, evidence, seal_store=store, quarantine=quarantine
    )
    dispositions = DispositionService(
        store, store, store, store, evidence, workflow, seal_store=store
    )
    sar = SarNarrativeService(
        store,
        store,
        store,
        store,
        evidence,
        approval_store=store,
        seal_store=store,
        review_store=store,
        quarantine=quarantine,
        gateway=gateway,
    )
    approvals = SarApprovalService(
        store, store, store, store, sar, evidence, workflow, seal_store=store
    )
    sealing = CaseSealingService(
        store, store, store, store, store, evidence, store
    )
    reviews = ContinuingReviewService(
        store,
        store,
        store,
        store,
        store,
        store,
        store,
        evidence,
        clocks,
        dispositions,
        seal_store=store,
        quarantine=quarantine,
    )
    profiles = ProfileService(
        store,
        store,
        store,
        store,
        evidence,
        dispositions=dispositions,
        approval_store=store,
        quarantine=quarantine,
    )
    investigations = InvestigationService(
        store,
        store,
        store,
        store,
        evidence,
        disposition_store=store,
        seal_store=store,
        quarantine=quarantine,
        profile_service=profiles,
        media_store=store,
        gateway=gateway,
    )
    media_feed = ListMediaFeed([])
    media = AdverseMediaService(
        store,
        store,
        evidence,
        media_feed,
        seal_store=store,
        quarantine=quarantine,
        profile_service=profiles,
        typology_store=store,
    )
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
        adverse_media_path=tmp_path / "media.json",
        model_profiles_path=tmp_path / "profiles.json",
        model_prices_path=tmp_path / "prices.json",
        model_profile="offline",
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
        approvals=approvals,
        sealing=sealing,
        clocks=clocks,
        reviews=reviews,
        quarantine=quarantine,
        profiles=profiles,
        media_feed=media_feed,
        media=media,
        gateway=gateway,
        reports=ReportingService(
            store,
            clocks,
            screening_store=store,
            typology_store=store,
            investigation_store=store,
            disposition_store=store,
            narrative_store=store,
            approval_store=store,
            review_store=store,
            media_store=store,
            ledger_store=store,
            quarantine=quarantine,
        ),
    )
