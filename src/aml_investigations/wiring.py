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
from .evidence import EvidenceService
from .intake import IntakeService, ReferenceAlertFeed
from .object_store import LocalObjectStore, S3ObjectStore
from .ports import AlertSource, CaseStore, ObjectStore, ScreeningListSource
from .screening import ReferenceScreeningFeed, ScreeningService
from .stores import SqlCaseStore
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
    )
