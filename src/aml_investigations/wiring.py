"""Composition root: builds the services from settings.

One place decides which adapters sit behind the ports, so the API,
the CLI, the demo, and the evals all run the same wiring rules:

- ``DATABASE_URL`` set -> Postgres case store; else SQLite file.
- ``S3_ENDPOINT_URL`` set -> S3-compatible object store; else local
  filesystem object store.
"""

from __future__ import annotations

from dataclasses import dataclass

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
from .screening import ReferenceScreeningFeed, ScreeningService
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
    evidence = EvidenceService(store, objects)
    workflow = CaseWorkflow(store, screening_store=store)
    alerts = ReferenceAlertFeed(settings.seed_alerts_path)
    intake = IntakeService(store, alerts, evidence)
    screening = ScreeningService(store, store, evidence)
    screening_feed = ReferenceScreeningFeed(settings.screening_lists_path)
    transactions = ReferenceTransactionFeed(settings.transaction_streams_path)
    typologies = TypologyService(store, store, evidence)
    rule_pack_feed = ReferenceRulePackFeed(settings.typology_rules_path)
    investigations = InvestigationService(
        store, store, store, store, evidence, disposition_store=store
    )
    dispositions = DispositionService(
        store, store, store, store, evidence, workflow
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
    )
