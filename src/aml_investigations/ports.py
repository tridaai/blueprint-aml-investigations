"""Ports: the interfaces every external system sits behind.

The blueprint never talks to a monitoring vendor, a database, or an
object store directly — it talks to these protocols, and each
deployment profile wires an adapter. Tests wire in-memory doubles
that honour the same contracts.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import (
    AccountProfile,
    Alert,
    AuditEvent,
    Case,
    DispositionConfirmation,
    DispositionRecord,
    EvidenceItem,
    InvestigationRecord,
    ListKind,
    ListSnapshot,
    RulePack,
    ScreeningHit,
    ScreeningRun,
    Transaction,
    TransactionBatch,
    TypologyFinding,
    TypologyRun,
)


@runtime_checkable
class CaseStore(Protocol):
    """Persistence for cases, evidence metadata, and the audit log."""

    def ping(self) -> bool: ...

    # --- cases -----------------------------------------------------
    def create_case(self, case: Case) -> Case: ...

    def get_case(self, case_id: str) -> Case | None: ...

    def get_case_by_alert(self, alert_id: str) -> Case | None: ...

    def update_case(self, case: Case) -> Case: ...

    def list_cases(self, status: str | None = None) -> list[Case]: ...

    # --- evidence metadata (blobs live in the ObjectStore) ---------
    def add_evidence_item(self, item: EvidenceItem) -> EvidenceItem: ...

    def list_evidence(self, case_id: str) -> list[EvidenceItem]: ...

    def get_evidence_item(self, case_id: str, seq: int) -> EvidenceItem | None: ...

    # --- audit ------------------------------------------------------
    def append_audit(self, event: AuditEvent) -> AuditEvent: ...

    def list_audit(self, case_id: str) -> list[AuditEvent]: ...


@runtime_checkable
class ObjectStore(Protocol):
    """Blob storage for evidence content (S3-compatible in production).

    There is deliberately no update or delete: evidence is immutable
    (Law 5). Corrections are new items in the case store.
    """

    def ping(self) -> bool: ...

    def put(self, key: str, content: bytes, media_type: str) -> None: ...

    def get(self, key: str) -> bytes: ...


@runtime_checkable
class AlertSource(Protocol):
    """The transaction-monitoring system, as an intake port."""

    def get_alert(self, alert_id: str) -> Alert | None: ...

    def list_alerts(self) -> list[Alert]: ...


@runtime_checkable
class ScreeningStore(Protocol):
    """Persistence for list snapshots, screening runs, and hits.

    There is deliberately no update or delete for snapshots: a
    snapshot, once ingested, is immutable (Law 3). Hits are the one
    mutable record — an analyst's clear/confirm is a status change
    with the reason kept on the hit and in the audit log.
    """

    def save_snapshot(self, snapshot: ListSnapshot) -> ListSnapshot: ...

    def get_snapshot(
        self, list_kind: ListKind, version: str
    ) -> ListSnapshot | None: ...

    def list_snapshots(
        self, list_kind: ListKind | None = None
    ) -> list[ListSnapshot]: ...

    def add_screening_run(self, run: ScreeningRun) -> ScreeningRun: ...

    def list_screening_runs(self, case_id: str) -> list[ScreeningRun]: ...

    def add_hit(self, hit: ScreeningHit) -> ScreeningHit: ...

    def get_hit(self, hit_id: str) -> ScreeningHit | None: ...

    def list_hits(self, case_id: str) -> list[ScreeningHit]: ...

    def update_hit(self, hit: ScreeningHit) -> ScreeningHit: ...


@runtime_checkable
class ScreeningListSource(Protocol):
    """Where snapshot definitions come from (a licensed list feed in
    production; a reference JSON file in the blueprint)."""

    def list_snapshots(self) -> list[ListSnapshot]: ...


@runtime_checkable
class TransactionSource(Protocol):
    """The core-banking transaction feed: an account's profile and
    its transaction stream. The contract is a full-history pull —
    the stream covers the account from opening — which is what lets
    the dormancy check measure the gap from the opening date. A
    deployment wires this to the bank's core; the blueprint ships a
    reference feed whose streams actually contain the patterns the
    seed alerts describe."""

    def list_account_ids(self) -> list[str]: ...

    def get_profile(self, account_id: str) -> AccountProfile | None: ...

    def get_transactions(self, account_id: str) -> list[Transaction]: ...


@runtime_checkable
class RulePackSource(Protocol):
    """Where rule-pack definitions come from (the bank's typology
    rule book, versioned; a reference JSON file in the blueprint)."""

    def list_rule_packs(self) -> list[RulePack]: ...


@runtime_checkable
class TypologyStore(Protocol):
    """Persistence for transaction batches/records, account
    profiles, rule packs, typology runs, and findings.

    Rule packs, like list snapshots, have no update or delete path:
    a registered pack never mutates (Law 4's versioning). Transaction
    records are only ever appended by batch ingestion, and findings
    only by an engine run.
    """

    def save_rule_pack(self, pack: RulePack) -> RulePack: ...

    def get_rule_pack(self, pack_id: str, version: str) -> RulePack | None: ...

    def list_rule_packs(self) -> list[RulePack]: ...

    def save_account_profile(self, profile: AccountProfile) -> AccountProfile: ...

    def get_account_profile(self, account_id: str) -> AccountProfile | None: ...

    def add_transaction_batch(self, batch: TransactionBatch) -> TransactionBatch: ...

    def get_transaction_batch(
        self, case_id: str, content_sha256: str
    ) -> TransactionBatch | None: ...

    def list_transaction_batches(self, case_id: str) -> list[TransactionBatch]: ...

    def add_transactions(
        self, case_id: str, batch_id: str, transactions: list[Transaction]
    ) -> None: ...

    def list_transactions(self, case_id: str) -> list[Transaction]: ...

    def add_typology_run(self, run: TypologyRun) -> TypologyRun: ...

    def list_typology_runs(self, case_id: str) -> list[TypologyRun]: ...

    def get_typology_run_by_fingerprint(
        self, case_id: str, pack_id: str, version: str, fingerprint: str
    ) -> TypologyRun | None: ...

    def add_finding(self, finding: TypologyFinding) -> TypologyFinding: ...

    def list_findings(self, case_id: str) -> list[TypologyFinding]: ...


@runtime_checkable
class InvestigationStore(Protocol):
    """Persistence for investigation records (R4).

    Records are append-only versions: a new investigation of a case
    adds the next version; no version is ever updated or deleted —
    supersession is a pointer on the newer record, so the case's
    full investigation history stays readable exactly as recorded.
    """

    def add_investigation_record(
        self, record: InvestigationRecord
    ) -> InvestigationRecord: ...

    def list_investigation_records(
        self, case_id: str
    ) -> list[InvestigationRecord]: ...

    def get_investigation_record(
        self, record_id: str
    ) -> InvestigationRecord | None: ...


@runtime_checkable
class DispositionStore(Protocol):
    """Persistence for disposition records and confirmations (R5).

    Both are append-only: a disposition is never updated or deleted
    (a later one supersedes it in the case view), and a confirmation
    is a separate record answering a disposition — the pair together
    is the gate's history, exactly as recorded.
    """

    def add_disposition(self, record: DispositionRecord) -> DispositionRecord: ...

    def list_dispositions(self, case_id: str) -> list[DispositionRecord]: ...

    def get_disposition(
        self, disposition_id: str
    ) -> DispositionRecord | None: ...

    def add_confirmation(
        self, confirmation: DispositionConfirmation
    ) -> DispositionConfirmation: ...

    def list_confirmations(
        self, case_id: str
    ) -> list[DispositionConfirmation]: ...

    def get_confirmation_for(
        self, disposition_id: str
    ) -> DispositionConfirmation | None: ...
