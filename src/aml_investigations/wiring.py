"""Composition root: builds the services from settings.

One place decides which adapters sit behind the ports, so the API,
the CLI, the demo, and the evals all run the same wiring rules:

- ``DATABASE_URL`` set -> Postgres case store; else SQLite file.
- ``S3_ENDPOINT_URL`` set -> S3-compatible object store; else local
  filesystem object store.
"""

from __future__ import annotations

from dataclasses import dataclass

from .access import AccessService
from .approval import SarApprovalService
from .clocks import RegulatoryClockService
from .config import Settings, load_settings
from .dispositions import DispositionService
from .evidence import EvidenceService
from .gateway import ModelGateway, load_gateway_files
from .intake import IntakeService, ReferenceAlertFeed
from .investigation import InvestigationService
from .media import AdverseMediaService, ReferenceMediaFeed
from .object_store import LocalObjectStore, S3ObjectStore
from .ports import (
    AdverseMediaSource,
    AlertSource,
    CaseStore,
    ObjectStore,
    RulePackSource,
    ScreeningListSource,
    TransactionSource,
)
from .profiles import ProfileService
from .quarantine import QuarantineService
from .reporting import ReportingService
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
    media_feed: AdverseMediaSource
    media: AdverseMediaService
    gateway: ModelGateway
    reports: ReportingService
    # R18: the access service is optional in the dataclass so
    # hand-built stacks (unit tests of a single service) keep
    # their old shape; production wiring always builds it, and
    # the API/CLI enforce through it whenever it is present.
    access: AccessService | None = None


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
    # R13: the model gateway — profiles + price table loaded and
    # validated fail-closed from the governed data files, the
    # deployment's own profile (AML_MODEL_PROFILE) resolved at
    # startup, every drafting call priced into the cost ledger,
    # budget refusals recorded on the case (ledger + audit +
    # chain). A broken profile table or an unconfigured active
    # profile refuses the boot here, not a later call.
    gateway = ModelGateway(
        load_gateway_files(
            settings.model_profiles_path, settings.model_prices_path
        ),
        store,
        audit_store=store,
        evidence=evidence,
        active_profile=settings.model_profile,
    )
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
    # R12: the adverse-media service searches the reference
    # corpus (a labelled stand-in for a licensed news database),
    # ingests candidates as evidence, and scores them in code.
    # The investigation graph reads its assessments through the
    # media store port.
    media_feed = ReferenceMediaFeed(settings.adverse_media_path)
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
    # R17: management reporting — a pure read-model over the
    # same stores and the R8 clock derivation. It writes
    # nothing; the pack it builds is content-addressed and
    # reproducible at its named as_of.
    reports = ReportingService(
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
    )
    # R18: access control — one check module in front of case
    # data, enforced by the API layer and the CLI. It writes
    # assignment acts through the evidence funnel (which brings
    # the sealed-case rule with it) and records denials on the
    # audit log.
    access = AccessService(store, evidence=evidence, seal_store=store)
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
        media_feed=media_feed,
        media=media,
        gateway=gateway,
        reports=reports,
        access=access,
    )
