"""Composition root: builds the services from settings.

One place decides which adapters sit behind the ports, so the API,
the CLI, the demo, and the evals all run the same wiring rules:

- ``DATABASE_URL`` set -> Postgres case store; else SQLite file.
- ``S3_ENDPOINT_URL`` set -> S3-compatible object store; else local
  filesystem object store.
"""

from __future__ import annotations

from dataclasses import dataclass

from .approval import SarApprovalService
from .clocks import RegulatoryClockService
from .config import Settings, load_settings
from .dispositions import DispositionService
from .evidence import EvidenceService
from .intake import IntakeService, ReferenceAlertFeed
from .investigation import InvestigationService
from .object_store import LocalObjectStore, S3ObjectStore
from .ports import (
    AlertSource,
    CaseStore,
    ObjectStore,
    RulePackSource,
    ScreeningListSource,
    TransactionSource,
)
from .profiles import ProfileService
from .quarantine import QuarantineService
from .reviews import ContinuingReviewService
from .sar import SarNarrativeService
from .screening import ReferenceScreeningFeed, ScreeningService
from .sealing import CaseSealingService
from .stores import SqlCaseStore
from .transactions import ReferenceRulePackFeed, ReferenceTransactionFeed
from .typologies import TypologyService
from .workflow import CaseWorkflow


@dataclass
class Services:
    settings: Settings
    store: CaseStore
    objects: ObjectStore
    evidence: EvidenceService
    workflow: CaseWorkflow
    alerts: AlertSource
    intake: IntakeService
    screening: ScreeningService
    screening_feed: ScreeningListSource
    transactions: TransactionSource
    typologies: TypologyService
    rule_pack_feed: RulePackSource
    investigations: InvestigationService
    dispositions: DispositionService
    sar: SarNarrativeService
    approvals: SarApprovalService
    sealing: CaseSealingService
    clocks: RegulatoryClockService
    reviews: ContinuingReviewService
    quarantine: QuarantineService
    profiles: ProfileService


def build_services(settings: Settings | None = None) -> Services:
    settings = settings or load_settings()
    if settings.use_postgres:
        store: CaseStore = SqlCaseStore.postgres(
            settings.database_url or "", settings.migrations_dir
        )
    else:
        store = SqlCaseStore.sqlite(settings.sqlite_path, settings.migrations_dir)
    if settings.s3_endpoint_url:
        objects: ObjectStore = S3ObjectStore(
            settings.s3_endpoint_url, settings.s3_bucket
        )
    else:
        objects = LocalObjectStore(settings.object_store_dir)
    evidence = EvidenceService(store, objects, seal_store=store)
    # R10: the quarantine service (Law 7). It writes through the
    # evidence funnel, so it is built after the funnel and then
    # attached as the funnel's scan hook; every ingestion and
    # consuming service takes it as the same shared instance.
    quarantine = QuarantineService(store, evidence, seal_store=store)
    evidence.quarantine = quarantine
    workflow = CaseWorkflow(store, screening_store=store)
    alerts = ReferenceAlertFeed(settings.seed_alerts_path)
    clocks = RegulatoryClockService(
        store, store, store, evidence, approvals=store, review_store=store
    )
    intake = IntakeService(
        store, alerts, evidence, clock_service=clocks, quarantine=quarantine
    )
    screening = ScreeningService(
        store, store, evidence, seal_store=store, quarantine=quarantine
    )
    screening_feed = ReferenceScreeningFeed(settings.screening_lists_path)
    transactions = ReferenceTransactionFeed(settings.transaction_streams_path)
    typologies = TypologyService(
        store, store, evidence, seal_store=store, quarantine=quarantine
    )
    rule_pack_feed = ReferenceRulePackFeed(settings.typology_rules_path)
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
    # R11: the profile service assembles KYC views from the same
    # stores; the investigation assembly consumes a stored view
    # for its profile facts when one exists, so the profile
    # service is built first and handed to it.
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
    )
    return Services(
        settings=settings,
        store=store,
        objects=objects,
        evidence=evidence,
        workflow=workflow,
        alerts=alerts,
        intake=intake,
        screening=screening,
        screening_feed=screening_feed,
        transactions=transactions,
        typologies=typologies,
        rule_pack_feed=rule_pack_feed,
        investigations=investigations,
        dispositions=dispositions,
        sar=sar,
        approvals=approvals,
        sealing=sealing,
        clocks=clocks,
        reviews=reviews,
        quarantine=quarantine,
        profiles=profiles,
    )
